defmodule Exosphere.ATProto.OAuth.SessionTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.{Client, ClientMetadata, JWK, ServerMetadata, Session}

  defp client do
    {:ok, key} = JWK.generate(:p256)

    metadata =
      ClientMetadata.new!(
        client_id: "https://app.example.com/oauth-client-metadata.json",
        redirect_uris: ["https://app.example.com/oauth/callback"],
        scope: ["atproto", "transition:generic"],
        jwk: JWK.to_public(key)
      )

    Client.new!(
      metadata: metadata,
      key: key,
      redirect_uri: "https://app.example.com/oauth/callback"
    )
  end

  defp auth_server do
    {:ok, metadata} =
      ServerMetadata.validate(
        %{
          "issuer" => "https://as.example.com",
          "authorization_endpoint" => "https://as.example.com/authorize",
          "token_endpoint" => "https://as.example.com/token",
          "pushed_authorization_request_endpoint" => "https://as.example.com/par",
          "response_types_supported" => ["code"],
          "grant_types_supported" => ["authorization_code", "refresh_token"],
          "scopes_supported" => ["atproto", "transition:generic"],
          "token_endpoint_auth_methods_supported" => ["none", "private_key_jwt"],
          "token_endpoint_auth_signing_alg_values_supported" => ["ES256"],
          "dpop_signing_alg_values_supported" => ["ES256"],
          "require_pushed_authorization_requests" => true,
          "client_id_metadata_document_supported" => true,
          "authorization_response_iss_parameter_supported" => true
        },
        "https://as.example.com"
      )

    metadata
  end

  defp session_opts(overrides \\ []) do
    {:ok, dpop_key} = JWK.generate(:p256)

    Keyword.merge(
      [
        sub: "did:web:alice.example.com",
        access_token: "at-1",
        refresh_token: "rt-1",
        scope: ["atproto", "transition:generic"],
        expires_in: 3600,
        dpop_key: dpop_key,
        client: client(),
        auth_server: auth_server(),
        expected_did: "did:web:alice.example.com",
        pds: "https://pds.example.com"
      ],
      overrides
    )
  end

  test "new/1 validates the subject against the expected DID" do
    assert {:ok, _} = Session.new(session_opts())
    assert {:error, :subject_mismatch} = Session.new(session_opts(expected_did: "did:web:other"))
  end

  test "new/1 requires DPoP token semantics" do
    assert {:error, {:missing_session_field, :dpop_key}} =
             Session.new(session_opts(dpop_key: nil))

    assert {:error, :atproto_scope_required} =
             Session.new(session_opts(scope: ["transition:generic"]))
  end

  test "new/1 accepts scope as a space-separated string" do
    assert {:ok, %{scope: ["atproto", "transition:generic"]}} =
             Session.new(session_opts(scope: "atproto transition:generic"))
  end

  test "expired?/2 honours expires_at with clock-skew allowance" do
    now = System.system_time(:second)
    assert Session.expired?(Session.new!(session_opts(expires_at: now + 100)), now: now) == false
    assert Session.expired?(Session.new!(session_opts(expires_at: now + 10)), now: now) == true
    assert Session.expired?(Session.new!(session_opts(expires_at: nil)), now: now) == false
  end

  test "refresh/2 rotates tokens and validates the response" do
    {:ok, session} = Session.new(session_opts())

    defmodule RotatingHTTP do
      def request(:post, url, opts) do
        assert url == "https://as.example.com/token"

        send(self(), {:form, URI.decode_query(opts[:body])})
        send(self(), {:dpop, List.keyfind(opts[:headers], "dpop", 0)})

        case Process.get(:token_responses) do
          [next | rest] ->
            Process.put(:token_responses, rest)
            next

          [] ->
            {:ok, %{status: 400, headers: [], body: %{"error" => "invalid_grant"}}}
        end
      end
    end

    Process.put(:token_responses, [
      {:ok,
       %{
         status: 200,
         headers: [],
         body: %{
           "access_token" => "at-2",
           "refresh_token" => "rt-2",
           "sub" => "did:web:alice.example.com",
           "scope" => "atproto transition:generic",
           "token_type" => "DPoP",
           "expires_in" => 3600
         }
       }}
    ])

    assert {:ok, refreshed} = Session.refresh(session, http: RotatingHTTP)
    assert refreshed.access_token == "at-2"
    assert refreshed.refresh_token == "rt-2"

    assert_received {:form,
                     %{
                       "grant_type" => "refresh_token",
                       "refresh_token" => "rt-1",
                       "client_id" => "https://app.example.com/oauth-client-metadata.json",
                       "client_assertion_type" =>
                         "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                       "client_assertion" => _
                     }}

    assert_received {:dpop, {"dpop", proof}}
    assert is_binary(proof)

    # The single-use refresh token is consumed; a second refresh is invalid
    assert {:error, {:refresh_failed, 400, %{"error" => "invalid_grant"}}} =
             Session.refresh(refreshed, http: RotatingHTTP)
  end

  test "refresh/2 without a refresh token fails fast" do
    {:ok, session} = Session.new(session_opts(refresh_token: nil))
    assert {:error, :no_refresh_token} = Session.refresh(session)
  end
end
