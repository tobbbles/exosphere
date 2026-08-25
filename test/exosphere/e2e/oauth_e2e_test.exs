defmodule Exosphere.OAuthE2ETest do
  @moduledoc """
  End-to-end ATProto OAuth flows against a local mock PDS/authorization
  server (`Exosphere.Test.MockPDS`), over real HTTP (Mint).

  These exercise the whole stack — did:web identity resolution,
  resource-server + authorization-server discovery, PAR with nonce
  challenges and retry, private_key_jwt client assertions, the authorize
  redirect, PKCE verification server-side, DPoP proof verification
  server-side (including `ath` binding and key continuity), token exchange,
  rotating refresh tokens, and DPoP-bound XRPC calls.
  """

  use ExUnit.Case, async: true

  alias Exosphere.ATProto.HTTP

  alias Exosphere.ATProto.OAuth.{
    Client,
    ClientMetadata,
    Discovery,
    Flow,
    JWK,
    PKCE,
    RequestContext,
    Session
  }

  alias Exosphere.OAuth.Session, as: SessionServer
  alias Exosphere.Test.MockPDS

  @redirect_uri "http://localhost:1/oauth/callback"

  setup do
    {:ok, mock} = MockPDS.start()
    on_exit(fn -> MockPDS.stop(mock) end)
    %{mock: mock}
  end

  defp confidential_client(mock) do
    {:ok, client_key} = JWK.generate(:p256)
    client_id = mock.origin <> "/oauth-client-metadata.json"

    metadata =
      ClientMetadata.new!(
        client_id: client_id,
        client_name: "Exosphere E2E",
        redirect_uris: [@redirect_uri],
        scope: ["atproto", "transition:generic"],
        jwk: JWK.to_public(client_key)
      )

    :ok = MockPDS.register_client(mock, ClientMetadata.to_document(metadata))
    Client.new!(metadata: metadata, key: client_key, redirect_uri: @redirect_uri)
  end

  defp run_flow(client, mock) do
    identifier = MockPDS.did(mock)

    with {:ok, resolved} <- Discovery.resolve(identifier),
         {:ok, {authorize_url, ctx}} <- Flow.authorize_url(client, resolved),
         {:ok, callback_params} <- follow_authorize_redirect(authorize_url) do
      Flow.callback(ctx, callback_params)
    end
  end

  defp follow_authorize_redirect(authorize_url) do
    assert {:ok, %{status: 302, headers: headers}} =
             HTTP.get(authorize_url, follow_redirects: false)

    {"location", location} = List.keyfind(headers, "location", 0)
    %URI{query: query} = URI.parse(location)
    {:ok, URI.decode_query(query)}
  end

  test "full confidential-client flow: discovery, PAR, PKCE, token, DPoP XRPC, refresh",
       %{mock: mock} do
    client = confidential_client(mock)

    # Discovery: did:web identity -> PDS -> (self) authorization server
    assert {:ok, resolved} = Discovery.resolve(MockPDS.did(mock))
    assert resolved.pds == mock.origin
    assert resolved.auth_server.issuer == mock.origin

    # PAR: the first request is nonce-challenged, the retry succeeds
    assert {:ok, {authorize_url, ctx}} = Flow.authorize_url(client, resolved)
    assert authorize_url =~ mock.origin <> "/authorize?client_id="
    assert authorize_url =~ "request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A"

    par_requests = for r <- MockPDS.requests(mock), r.path == "/par", do: r
    assert length(par_requests) == 2

    # Authorize redirect carries code, state, and iss
    {:ok, params} = follow_authorize_redirect(authorize_url)
    assert params["iss"] == mock.origin
    assert params["state"] == ctx.state
    assert String.starts_with?(params["code"], "ac-")

    # Token exchange produces a DPoP-bound session for the resolved identity
    assert {:ok, session} = Flow.callback(ctx, params)
    assert session.sub == MockPDS.did(mock)
    assert session.access_token =~ "at-"
    assert session.refresh_token =~ "rt-"
    assert session.scope == ["atproto", "transition:generic"]
    assert session.pds == mock.origin

    # DPoP-bound XRPC call through the session process (server verifies the
    # proof: method, URI, ath, and nonce)
    {:ok, pid} = SessionServer.start_link(session: session)

    assert {:ok, %{"did" => did}} =
             SessionServer.query(pid, "com.atproto.repo.describeRepo", repo: session.sub)

    assert did == session.sub

    # Refresh rotates both tokens; the old refresh token is single-use
    old_refresh = session.refresh_token
    assert {:ok, refreshed} = SessionServer.refresh(pid)
    assert refreshed.refresh_token != old_refresh
    assert refreshed.sub == session.sub

    assert {:error, {:refresh_failed, 400, %{"error" => "invalid_grant"}}} =
             Session.refresh(%{refreshed | refresh_token: old_refresh})
  end

  test "DPoP nonce rotation mid-session is retried transparently", %{mock: mock} do
    client = confidential_client(mock)
    {:ok, session} = run_flow(client, mock)

    # Fresh session: the nonce cached from the token exchange is current
    {:ok, pid} = SessionServer.start_link(session: session)
    MockPDS.rotate_nonce(mock)

    assert {:ok, %{"did" => _}} =
             SessionServer.query(pid, "com.atproto.repo.describeRepo", repo: session.sub)

    xrpc_requests = for r <- MockPDS.requests(mock), r.path =~ ~r{^/xrpc/}, do: r
    assert length(xrpc_requests) == 2
  end

  test "request context round-trips through a JSON-encodable map", %{mock: mock} do
    client = confidential_client(mock)
    identifier = MockPDS.did(mock)

    assert {:ok, resolved} = Discovery.resolve(identifier)
    assert {:ok, {_url, ctx}} = Flow.authorize_url(client, resolved)

    encoded = ctx |> RequestContext.to_map() |> Jason.encode!()
    assert {:ok, json} = Jason.decode(encoded)
    {:ok, decoded} = RequestContext.from_map(json)

    assert decoded.state == ctx.state
    assert decoded.verifier == ctx.verifier
    assert decoded.client == ctx.client
    assert decoded.auth_server.issuer == ctx.auth_server.issuer
    assert decoded.expected_did == ctx.expected_did
  end

  test "session round-trips through a JSON-encodable map", %{mock: mock} do
    client = confidential_client(mock)
    {:ok, session} = run_flow(client, mock)

    encoded = session |> Session.to_map() |> Jason.encode!()
    assert {:ok, json} = Jason.decode(encoded)
    {:ok, decoded} = Session.from_map(json)

    assert decoded.sub == session.sub
    assert decoded.access_token == session.access_token
    assert decoded.dpop_key == session.dpop_key

    # The restored session can still make DPoP-bound calls and refresh
    {:ok, pid} = SessionServer.start_link(session: decoded)

    assert {:ok, %{"did" => _}} =
             SessionServer.query(pid, "com.atproto.repo.describeRepo", repo: decoded.sub)

    assert {:ok, _} = SessionServer.refresh(pid)
  end

  test "callback rejects a mismatched state", %{mock: mock} do
    client = confidential_client(mock)
    identifier = MockPDS.did(mock)

    assert {:ok, resolved} = Discovery.resolve(identifier)
    assert {:ok, {authorize_url, ctx}} = Flow.authorize_url(client, resolved)
    {:ok, params} = follow_authorize_redirect(authorize_url)

    assert {:error, :state_mismatch} = Flow.callback(ctx, %{params | "state" => "attacker"})
  end

  test "callback rejects a mismatched issuer (iss)", %{mock: mock} do
    client = confidential_client(mock)
    identifier = MockPDS.did(mock)

    assert {:ok, resolved} = Discovery.resolve(identifier)
    assert {:ok, {authorize_url, ctx}} = Flow.authorize_url(client, resolved)
    {:ok, params} = follow_authorize_redirect(authorize_url)

    assert {:error, :issuer_mismatch} =
             Flow.callback(ctx, %{params | "iss" => "https://evil.example.com"})
  end

  test "public loopback client (client_id http://localhost) completes the flow", %{mock: mock} do
    {:ok, client_id} = ClientMetadata.localhost_client_id([@redirect_uri])

    metadata =
      ClientMetadata.new!(client_id: client_id, redirect_uris: [@redirect_uri])

    client = Client.new!(metadata: metadata, redirect_uri: @redirect_uri)
    refute Client.confidential?(client)

    assert {:ok, session} = run_flow(client, mock)
    assert session.sub == MockPDS.did(mock)

    {:ok, pid} = SessionServer.start_link(session: session)

    assert {:ok, %{"did" => _}} =
             SessionServer.query(pid, "com.atproto.repo.describeRepo", repo: session.sub)
  end

  test "server flow: start from a server URL, verify the subject after exchange", %{mock: mock} do
    client = confidential_client(mock)

    # No identity resolution: straight to the server's own metadata
    assert {:ok, resolved} = Discovery.resolve(mock.origin)
    assert is_nil(resolved.did)
    assert resolved.auth_server.issuer == mock.origin

    assert {:ok, {authorize_url, ctx}} = Flow.authorize_url(client, resolved)
    assert is_nil(ctx.expected_did)

    {:ok, params} = follow_authorize_redirect(authorize_url)

    # The token response's sub is now unknown — it must be verified against
    # the issuer (DID -> PDS -> resource-server metadata -> issuer match)
    assert {:ok, session} = Flow.callback(ctx, params)
    assert session.sub == MockPDS.did(mock)
    assert session.pds == mock.origin
  end

  test "entryway relocation: a PDS served by a separate authorization server", %{
    mock: entryway
  } do
    {:ok, pds} = MockPDS.start(entryway: entryway.origin)
    on_exit(fn -> MockPDS.stop(pds) end)

    # The account lives on the PDS; authorization happens at the entryway
    assert {:ok, resolved} = Discovery.resolve(MockPDS.did(pds))
    assert resolved.pds == pds.origin
    assert resolved.auth_server.issuer == entryway.origin

    client = confidential_client(entryway)
    assert {:ok, {authorize_url, ctx}} = Flow.authorize_url(client, resolved)

    {:ok, params} = follow_authorize_redirect(authorize_url)
    assert params["iss"] == entryway.origin

    assert {:ok, session} = Flow.callback(ctx, params)
    assert session.sub == MockPDS.did(pds)
    assert session.pds == pds.origin

    # PAR and token were served by the entryway, not the PDS
    assert Enum.any?(MockPDS.requests(entryway), &(&1.path == "/par"))
    assert Enum.any?(MockPDS.requests(entryway), &(&1.path == "/token"))
    refute Enum.any?(MockPDS.requests(pds), &(&1.path in ["/par", "/token"]))
  end

  test "PKCE is enforced server-side: a wrong verifier fails the exchange", %{mock: mock} do
    client = confidential_client(mock)
    identifier = MockPDS.did(mock)

    assert {:ok, resolved} = Discovery.resolve(identifier)
    assert {:ok, {authorize_url, ctx}} = Flow.authorize_url(client, resolved)
    {:ok, params} = follow_authorize_redirect(authorize_url)

    tampered = %RequestContext{ctx | verifier: PKCE.generate_verifier()}
    assert {:error, {:token_exchange_failed, 400, _}} = Flow.callback(tampered, params)
  end

  test "the DPoP key must stay the same across PAR and token exchange", %{mock: mock} do
    client = confidential_client(mock)
    identifier = MockPDS.did(mock)

    assert {:ok, resolved} = Discovery.resolve(identifier)
    assert {:ok, {authorize_url, ctx}} = Flow.authorize_url(client, resolved)
    {:ok, params} = follow_authorize_redirect(authorize_url)

    {:ok, other_key} = JWK.generate(:p256)
    hijacked = %RequestContext{ctx | dpop_key: other_key}
    assert {:error, {:token_exchange_failed, 400, _}} = Flow.callback(hijacked, params)
  end
end
