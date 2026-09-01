defmodule Exosphere.ATProto.Spaces.CredentialTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Base58
  alias Exosphere.ATProto.Identity.Document
  alias Exosphere.ATProto.OAuth.{DPoP, JWK}
  alias Exosphere.ATProto.Spaces.Credential
  alias Exosphere.ATProto.Spaces.Token

  @pds "https://pds.example.com"
  @space_host "https://space-host.example.com"
  @authority "did:plc:spaceauthority"
  @user "did:plc:alice"
  @space "at://" <> @authority <> "/space/com.example.group/default"
  @client_id "https://app.example.com/client-metadata.json"
  @now 1_800_000_000

  # Mocks record the last request in the process dictionary and serve the
  # response the test staged there — each test process has its own.
  defmodule RecordingHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    @impl true
    def get(url, opts \\ []) do
      Process.put(:last_get, {url, opts})
      staged(:get_response, {:ok, %{status: 404, headers: [], body: %{}}})
    end

    @impl true
    def post(url, opts \\ []) do
      Process.put(:last_post, {url, opts})
      staged(:post_response, {:ok, %{status: 404, headers: [], body: %{}}})
    end

    @impl true
    def request(method, url, opts \\ []),
      do: (method == :get && get(url, opts)) || post(url, opts)

    defp staged(key, default) do
      Process.get(key) || default
    end
  end

  setup do
    {:ok, user} = JWK.generate(:secp256k1)
    {:ok, authority} = JWK.generate(:secp256k1)
    {:ok, app} = JWK.generate(:p256)
    {:ok, dpop_key} = DPoP.generate_key()

    %{
      user: user,
      authority: authority,
      app: app,
      dpop_key: dpop_key,
      authority_doc: did_document(@authority, authority)
    }
  end

  defp delegation_jwt(ctx, opts \\ []) do
    {:ok, jwt} =
      Token.sign(
        :delegation,
        [iss: @user, sub: @space, aud: Token.space_host_aud(@authority), iat: @now] ++ opts,
        ctx.user
      )

    jwt
  end

  defp credential_jwt(ctx, dpop_key) do
    {:ok, jkt} = JWK.thumbprint(JWK.to_public(dpop_key))

    {:ok, jwt} =
      Token.sign(
        :credential,
        [iss: @authority, sub: @space, dpop_jkt: jkt, iat: @now],
        ctx.authority
      )

    jwt
  end

  test "get_delegation_token calls the PDS OAuth-authed with the space ref", ctx do
    delegation = delegation_jwt(ctx)

    Process.put(:get_response, {:ok, %{status: 200, headers: [], body: %{"token" => delegation}}})

    assert {:ok, ^delegation} =
             Credential.get_delegation_token(@pds, @space,
               headers: [{"authorization", "Bearer tok"}],
               http: RecordingHTTP
             )

    {url, opts} = Process.get(:last_get)

    assert url ==
             @pds <>
               "/xrpc/com.atproto.space.getDelegationToken?space=" <>
               URI.encode_www_form(@space)

    assert {"authorization", "Bearer tok"} in (opts[:headers] || [])
  end

  test "get_delegation_token surfaces http errors" do
    Process.put(
      :get_response,
      {:ok, %{status: 401, headers: [], body: %{"error" => "ExpiredToken"}}}
    )

    assert {:error, {:http_error, 401}} =
             Credential.get_delegation_token(@pds, @space, http: RecordingHTTP)
  end

  test "mint exchanges a delegation for a DPoP-bound credential", ctx do
    delegation = delegation_jwt(ctx)
    credential = credential_jwt(ctx, ctx.dpop_key)

    Process.put(
      :post_response,
      {:ok, %{status: 200, headers: [], body: %{"credential" => credential}}}
    )

    assert {:ok, %{credential: ^credential}} =
             Credential.mint(@space_host, @space, delegation,
               dpop_key: ctx.dpop_key,
               http: RecordingHTTP
             )

    {url, opts} = Process.get(:last_post)
    assert url == @space_host <> "/xrpc/com.atproto.space.getSpaceCredential"

    assert {"authorization", "DPoP " <> delegation} in (opts[:headers] || [])

    assert {:ok, dpop} = find_header(opts[:headers], "dpop")
    assert {:ok, _} = DPoP.verify_proof(dpop, "POST", url)

    assert opts[:json]["space"] == @space
    refute Map.has_key?(opts[:json], "clientAttestation")

    # The exchange proof is signed by exactly the key the credential binds to.
    {:ok, proof} = find_header(opts[:headers], "dpop")
    {:ok, jkt} = JWK.thumbprint(JWK.to_public(ctx.dpop_key))
    assert {:ok, %{jkt: ^jkt}} = DPoP.verify_proof(proof, "POST", url)
  end

  test "mint carries a client attestation when gating", ctx do
    delegation = delegation_jwt(ctx)
    credential = credential_jwt(ctx, ctx.dpop_key)

    Process.put(
      :post_response,
      {:ok, %{status: 200, headers: [], body: %{"credential" => credential}}}
    )

    {:ok, attestation} =
      Credential.mint_client_attestation(
        @client_id,
        Token.space_host_aud(@authority),
        ctx.app,
        iat: @now
      )

    assert {:ok, _} =
             Credential.mint(@space_host, @space, delegation,
               dpop_key: ctx.dpop_key,
               client_attestation: attestation,
               http: RecordingHTTP
             )

    {_url, opts} = Process.get(:last_post)
    assert opts[:json]["clientAttestation"] == attestation
  end

  test "mint catches a credential bound to another key", ctx do
    delegation = delegation_jwt(ctx)

    {:ok, evil_key} = DPoP.generate_key()
    evil = credential_jwt(ctx, evil_key)

    Process.put(:post_response, {:ok, %{status: 200, headers: [], body: %{"credential" => evil}}})

    assert {:error, :credential_bound_to_other_key} =
             Credential.mint(@space_host, @space, delegation,
               dpop_key: ctx.dpop_key,
               http: RecordingHTTP
             )
  end

  test "mint surfaces host refusals with their error code", ctx do
    delegation = delegation_jwt(ctx)

    Process.put(
      :post_response,
      {:ok, %{status: 403, headers: [], body: %{"error" => "UserNotAuthorized"}}}
    )

    assert {:error, {:http_error, 403, "UserNotAuthorized"}} =
             Credential.mint(@space_host, @space, delegation,
               dpop_key: ctx.dpop_key,
               http: RecordingHTTP
             )
  end

  test "mint passes transport errors through instead of crashing" do
    Process.put(:post_response, {:error, :econnrefused})

    assert {:error, :econnrefused} =
             Credential.mint(@space_host, @space, "jwt",
               dpop_key: dp_key(),
               http: RecordingHTTP
             )
  end

  test "mint requires a dpop key" do
    assert {:error, :missing_dpop_key} =
             Credential.mint(@space_host, @space, "jwt", http: RecordingHTTP)
  end

  test "verify resolves the authority's space key from its DID document", ctx do
    credential = credential_jwt(ctx, ctx.dpop_key)
    assert {:ok, %{payload: payload}} = Credential.verify(credential, ctx.authority_doc)
    assert payload["iss"] == @authority
    assert payload["sub"] == @space
  end

  test "verify rejects a credential signed by the wrong authority", ctx do
    {:ok, other} = JWK.generate(:secp256k1)
    credential = credential_jwt(ctx, ctx.dpop_key)
    doc = did_document(@authority, other)

    assert {:error, :invalid_signature} = Credential.verify(credential, doc)
  end

  test "verify honours an explicit expected subject", ctx do
    credential = credential_jwt(ctx, ctx.dpop_key)

    assert {:error, :bad_subject} =
             Credential.verify(credential,
               get_signing_key: fn _, _, _ -> {:ok, JWK.to_public(ctx.authority)} end,
               sub: "at://other"
             )
  end

  # -- the credential's `kid` -----------------------------------------------
  #
  # `kid` is the class *default*, not a constant: the header must name the
  # fragment the signing key was published under, because a verifier that
  # honours `kid` resolves that verification method and nothing else. The
  # authority in these tests publishes both, which is the only configuration
  # where guessing and honouring differ.

  test "a credential signed with a published space key names #atproto_space", ctx do
    {:ok, space_jwk} = JWK.generate(:secp256k1)
    credential = signed_credential(space_jwk, ctx.dpop_key, kid: "#atproto_space")

    assert {:ok, %{header: header}} = Token.parse(:credential, credential)
    assert header["kid"] == "#atproto_space"

    doc = did_document(@authority, ctx.authority, [{"#atproto_space", space_jwk}])
    assert {:ok, %{payload: payload}} = Credential.verify(credential, doc)
    assert payload["sub"] == @space
  end

  test "verify resolves #atproto when that is the key the credential names", ctx do
    # An authority whose space signing key *is* its account key — every
    # authority hosted on a PDS, and what the reference does — signs with
    # `#atproto` even where a space key is also published. Preferring the
    # space key would fail a perfectly good signature.
    {:ok, space_jwk} = JWK.generate(:secp256k1)
    credential = credential_jwt(ctx, ctx.dpop_key)
    doc = did_document(@authority, ctx.authority, [{"#atproto_space", space_jwk}])

    assert {:ok, %{payload: %{"iss" => @authority}}} = Credential.verify(credential, doc)
  end

  test "verify rejects a credential whose kid names a key it was not signed with", ctx do
    # Signed with the space key, stamped `#atproto`: the mismatch a verifier
    # that ignores `kid` never notices.
    {:ok, space_jwk} = JWK.generate(:secp256k1)
    credential = signed_credential(space_jwk, ctx.dpop_key, [])
    doc = did_document(@authority, ctx.authority, [{"#atproto_space", space_jwk}])

    assert {:error, :invalid_signature} = Credential.verify(credential, doc)
  end

  test "verify refuses a kid naming an unrelated verification method", ctx do
    credential = signed_credential(ctx.authority, ctx.dpop_key, kid: "#atproto_labeler")

    assert {:error, :unsupported_space_kid} =
             Credential.verify(credential, did_document(@authority, ctx.authority))
  end

  test "verify reports a kid the authority never published", ctx do
    {:ok, space_jwk} = JWK.generate(:secp256k1)
    credential = signed_credential(space_jwk, ctx.dpop_key, kid: "#atproto_space")

    assert {:error, :not_found} =
             Credential.verify(credential, did_document(@authority, ctx.authority))
  end

  test "verify accepts an absolute kid, not only a bare fragment", ctx do
    {:ok, space_jwk} = JWK.generate(:secp256k1)

    credential =
      signed_credential(space_jwk, ctx.dpop_key, kid: @authority <> "#atproto_space")

    doc = did_document(@authority, ctx.authority, [{"#atproto_space", space_jwk}])
    assert {:ok, _} = Credential.verify(credential, doc)
  end

  # -- request options reach the transport ----------------------------------

  test "get_delegation_token hands the caller's timeout to the transport", ctx do
    delegation = delegation_jwt(ctx)
    Process.put(:get_response, {:ok, %{status: 200, headers: [], body: %{"token" => delegation}}})

    assert {:ok, ^delegation} =
             Credential.get_delegation_token(@pds, @space,
               headers: [{"authorization", "Bearer tok"}],
               timeout: 1_500,
               http: RecordingHTTP
             )

    {_url, opts} = Process.get(:last_get)
    assert opts[:timeout] == 1_500
    assert {"authorization", "Bearer tok"} in opts[:headers]
  end

  test "mint hands the caller's timeout to the transport", ctx do
    delegation = delegation_jwt(ctx)
    credential = credential_jwt(ctx, ctx.dpop_key)

    Process.put(
      :post_response,
      {:ok, %{status: 200, headers: [], body: %{"credential" => credential}}}
    )

    assert {:ok, _} =
             Credential.mint(@space_host, @space, delegation,
               dpop_key: ctx.dpop_key,
               timeout: 1_500,
               follow_redirects: false,
               http: RecordingHTTP
             )

    {_url, opts} = Process.get(:last_post)
    assert opts[:timeout] == 1_500
    assert opts[:follow_redirects] == false

    # The exchange's own options are not the caller's to displace.
    assert opts[:json]["space"] == @space

    assert {"authorization", "DPoP " <> ^delegation} =
             List.keyfind(opts[:headers], "authorization", 0)
  end

  test "mint keeps its authorization when the caller passes headers of their own", ctx do
    delegation = delegation_jwt(ctx)
    credential = credential_jwt(ctx, ctx.dpop_key)

    Process.put(
      :post_response,
      {:ok, %{status: 200, headers: [], body: %{"credential" => credential}}}
    )

    assert {:ok, _} =
             Credential.mint(@space_host, @space, delegation,
               dpop_key: ctx.dpop_key,
               headers: [{"authorization", "Bearer not-this-one"}],
               http: RecordingHTTP
             )

    {_url, opts} = Process.get(:last_post)

    assert {"authorization", "DPoP " <> ^delegation} =
             List.keyfind(opts[:headers], "authorization", 0)
  end

  # The mocks above prove the option is in the list; this proves it reaches
  # the socket. Against a server that accepts and never answers, a dropped
  # `:timeout` waits out the 30s default instead of the 100ms asked for.
  @tag timeout: 5_000
  test "a configured timeout reaches the transport, not just the option list" do
    {:ok, listen} = :gen_tcp.listen(0, [:inet, :binary, {:active, false}])
    {:ok, port} = :inet.port(listen)

    {:ok, _server} =
      Task.start_link(fn ->
        {:ok, sock} = :gen_tcp.accept(listen, 4_000)
        :gen_tcp.recv(sock, 0, 4_000)
        Process.sleep(4_000)
      end)

    started = System.monotonic_time(:millisecond)

    assert {:error, :timeout} =
             Credential.get_delegation_token("http://127.0.0.1:#{port}", @space, timeout: 100)

    assert System.monotonic_time(:millisecond) - started < 2_000
    :gen_tcp.close(listen)
  end

  defp signed_credential(jwk, dpop_key, opts) do
    {:ok, jkt} = JWK.thumbprint(JWK.to_public(dpop_key))

    {:ok, jwt} =
      Token.sign(
        :credential,
        [iss: @authority, sub: @space, dpop_jkt: jkt, iat: @now] ++ opts,
        jwk
      )

    jwt
  end

  defp dp_key do
    {:ok, key} = DPoP.generate_key()
    key
  end

  defp find_header(headers, name) do
    case List.keyfind(headers || [], name, 0) do
      {^name, value} -> {:ok, value}
      _ -> :error
    end
  end

  # The account key under `#atproto`, plus any `{fragment, jwk}` the test
  # wants the authority to publish alongside it.
  defp did_document(did, jwk, extra \\ []) do
    methods =
      [verification_method(did, "#atproto", jwk)] ++
        Enum.map(extra, fn {fragment, key} -> verification_method(did, fragment, key) end)

    {:ok, doc} =
      Document.parse(%{
        "id" => did,
        "verificationMethod" => methods,
        "service" => [
          %{
            "id" => did <> "#atproto_pds",
            "type" => "AtprotoPersonalDataServer",
            "serviceEndpoint" => @pds
          }
        ]
      })

    doc
  end

  defp verification_method(did, fragment, jwk) do
    {:ok, public_key, :secp256k1} = JWK.to_public_key(JWK.to_public(jwk))

    %{
      "id" => did <> fragment,
      "type" => "Multikey",
      "controller" => did,
      "publicKeyMultibase" => "z" <> Base58.encode(<<0xE7, 0x01, public_key::binary>>)
    }
  end
end
