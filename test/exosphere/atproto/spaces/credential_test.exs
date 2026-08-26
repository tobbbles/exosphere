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

  defp did_document(did, jwk) do
    {:ok, public_key, :secp256k1} = JWK.to_public_key(JWK.to_public(jwk))
    multibase = "z" <> Base58.encode(<<0xE7, 0x01, public_key::binary>>)

    {:ok, doc} =
      Document.parse(%{
        "id" => did,
        "verificationMethod" => [
          %{
            "id" => did <> "#atproto",
            "type" => "Multikey",
            "controller" => did,
            "publicKeyMultibase" => multibase
          }
        ],
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
end
