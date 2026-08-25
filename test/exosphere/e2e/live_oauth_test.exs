defmodule Exosphere.LiveOAuthTest do
  @moduledoc """
  Live discovery checks against the real Bluesky infrastructure.

  Excluded from the default run (`mix test`); opt in with:

      mix test --only live

  These only exercise read-only discovery (handle → DID → PDS →
  resource-server metadata → authorization-server metadata) — no PAR or
  token requests, which would need a publicly hosted `client_id` document.
  """

  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.Discovery

  @tag :live
  test "resolve/2 walks a real handle through to bsky.social's entryway" do
    assert {:ok, resolved} = Discovery.resolve("atproto.com", timeout: 15_000)

    assert String.starts_with?(resolved.did, "did:plc:")
    assert is_binary(resolved.pds)
    assert %{issuer: issuer} = resolved.auth_server
    assert URI.parse(issuer).host != nil

    assert resolved.auth_server.pushed_authorization_request_endpoint =~ "/par"
    assert resolved.auth_server.token_endpoint =~ "/token"
  end

  @tag :live
  test "resolve/2 accepts a bare server origin (bsky.social)" do
    assert {:ok, resolved} = Discovery.resolve("https://bsky.social", timeout: 15_000)
    assert is_nil(resolved.did)
    assert String.starts_with?(resolved.auth_server.issuer, "https://")
  end

  @tag :live
  test "resolve/2 rejects a handle claimed by a different DID" do
    # did:plc:ewvi7nx4oun5m6s5q5yza2a? — whatever "atproto.com" resolves to,
    # this handle does not exist, so resolution must fail cleanly
    assert {:error, _} =
             Discovery.resolve("no-such-handle-#{System.unique_integer()}.example.com",
               timeout: 15_000
             )
  end
end
