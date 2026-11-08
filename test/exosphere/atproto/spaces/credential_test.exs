defmodule Exosphere.ATProto.Spaces.CredentialTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Base58
  alias Exosphere.ATProto.Identity.Document
  alias Exosphere.ATProto.OAuth.{DPoP, JWK, Session}
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

  # A resource server that challenges the first request for a DPoP nonce
  # (401 + DPoP-Nonce, as a PDS does) and serves the staged response after.
  defmodule NonceHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    @impl true
    def get(url, opts \\ []), do: request(:get, url, opts)

    @impl true
    def post(url, opts \\ []), do: request(:post, url, opts)

    @impl true
    def request(method, url, opts \\ []) do
      seen = Process.get(:nonce_requests, [])
      Process.put(:nonce_requests, seen ++ [{method, url, opts}])

      if seen == [] do
        {:ok,
         %{
           status: 401,
           headers: [
             {"www-authenticate", ~s(DPoP error="use_dpop_nonce")},
             {"dpop-nonce", "nonce-1"}
           ],
           body: %{"error" => "use_dpop_nonce"}
         }}
      else
        Process.get(:nonce_response) || {:ok, %{status: 200, headers: [], body: %{}}}
      end
    end
  end

  defp proof_claims(headers) do
    {"dpop", proof} = List.keyfind(headers, "dpop", 0)
    [_header, payload, _sig] = String.split(proof, ".")
    payload |> Base.url_decode64!(padding: false) |> Jason.decode!()
  end

  # NonceStore is global and keyed by origin; a unique host keeps async tests
  # from seeing each other's nonces.
  defp unique_pds, do: "https://pds-#{System.unique_integer([:positive])}.example.com"

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

  test "get_delegation_token DPoP-signs under an OAuth session, with nonce retry", ctx do
    delegation = delegation_jwt(ctx)
    pds = unique_pds()

    session = %Session{
      sub: @user,
      access_token: "access-jwt",
      scope: ["atproto"],
      pds: pds,
      dpop_key: ctx.dpop_key
    }

    Process.put(
      :nonce_response,
      {:ok, %{status: 200, headers: [], body: %{"token" => delegation}}}
    )

    assert {:ok, ^delegation} =
             Credential.get_delegation_token(pds, @space, session: session, http: NonceHTTP)

    assert [{:get, url, first}, {:get, url, retry}] = Process.get(:nonce_requests)
    assert String.starts_with?(url, pds <> "/xrpc/com.atproto.space.getDelegationToken?space=")

    # DPoP scheme, never Bearer: the session's access token is DPoP-bound.
    assert {"authorization", "DPoP access-jwt"} in retry[:headers]
    refute Enum.any?(retry[:headers], &match?({"authorization", "Bearer " <> _}, &1))

    {"dpop", proof} = List.keyfind(retry[:headers], "dpop", 0)
    assert {:ok, _} = DPoP.verify_proof(proof, "GET", url, credential: "access-jwt")
    refute Map.has_key?(proof_claims(first[:headers]), "nonce")
    assert proof_claims(retry[:headers])["nonce"] == "nonce-1"
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
  # Since atproto `432ef66` a credential's `kid` is exactly `#atproto`: the
  # dedicated `#atproto_space` key is gone, and a verifier resolves the
  # authority's account key and nothing else.

  test "verify resolves the #atproto key even where a stale #atproto_space is published",
       ctx do
    {:ok, space_jwk} = JWK.generate(:secp256k1)
    credential = credential_jwt(ctx, ctx.dpop_key)
    doc = did_document(@authority, ctx.authority, [{"#atproto_space", space_jwk}])

    assert {:ok, %{payload: %{"iss" => @authority}}} = Credential.verify(credential, doc)
  end

  test "verify rejects a credential signed with a key other than #atproto", ctx do
    {:ok, space_jwk} = JWK.generate(:secp256k1)
    credential = signed_credential(space_jwk, ctx.dpop_key, [])
    doc = did_document(@authority, ctx.authority, [{"#atproto_space", space_jwk}])

    assert {:error, :invalid_signature} = Credential.verify(credential, doc)
  end

  test "sign refuses a kid override for a credential", ctx do
    {:ok, jkt} = JWK.thumbprint(JWK.to_public(ctx.dpop_key))

    assert {:error, :fixed_kid} =
             Token.sign(
               :credential,
               [iss: @authority, sub: @space, dpop_jkt: jkt, kid: "#atproto_space"],
               ctx.authority
             )
  end

  test "verify refuses a credential whose header names any other kid", ctx do
    {:ok, jkt} = JWK.thumbprint(JWK.to_public(ctx.dpop_key))

    for kid <- ["#atproto_space", "#atproto_labeler", @authority <> "#atproto", nil] do
      header =
        %{"alg" => "ES256K", "typ" => "atproto-space-credential+jwt"}
        |> then(&if(kid, do: Map.put(&1, "kid", kid), else: &1))

      payload = %{
        "iss" => @authority,
        "sub" => @space,
        "cnf" => %{"jkt" => jkt},
        "iat" => @now,
        "exp" => @now + 600,
        "jti" => "j"
      }

      {:ok, jwt} = Exosphere.ATProto.OAuth.JWS.sign(ctx.authority, header, payload)

      assert {:error, :invalid_kid} =
               Credential.verify(jwt, did_document(@authority, ctx.authority))
    end
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
