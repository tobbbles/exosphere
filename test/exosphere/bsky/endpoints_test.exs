defmodule Exosphere.Bsky.EndpointsTest do
  @moduledoc """
  Validates generated XRPC endpoint modules against a fake HTTP backend:
  param validation, wire encoding into the query string, procedure bodies,
  and error paths.
  """

  use ExUnit.Case, async: true

  alias Exosphere.ATProto.XRPC.Client
  alias Exosphere.Bsky.{Actor, Feed, Graph, Video}

  defmodule FakeHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    def get(url, _opts \\ []) do
      send(self(), {:get, url})
      {:ok, %{status: 200, body: %{"ok" => true}}}
    end

    def post(url, opts \\ []) do
      send(self(), {:post, url, opts[:json]})
      {:ok, %{status: 200, body: %{"ok" => true}}}
    end
  end

  defp client do
    Client.new("https://public.api.bsky.app", http: FakeHTTP)
  end

  test "query builds the XRPC URL with encoded params" do
    assert {:ok, _} = Actor.get_profile(client(), %{"actor" => "alice.bsky.social"})

    assert_received {:get, url}

    assert url ==
             "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=alice.bsky.social"
  end

  test "query accepts atom or string keys and encodes non-strings" do
    assert {:ok, _} = Feed.get_timeline(client(), limit: 25)
    assert_received {:get, url}
    assert url == "https://public.api.bsky.app/xrpc/app.bsky.feed.getTimeline?limit=25"

    assert {:ok, _} = Feed.get_timeline(client(), %{"limit" => 10})
    assert_received {:get, url}
    assert url == "https://public.api.bsky.app/xrpc/app.bsky.feed.getTimeline?limit=10"
  end

  test "required params are enforced" do
    assert {:error, [{"actor", "is required"}]} = Actor.get_profile(client(), %{})

    assert {:error, [{"actor", "is not a valid at-identifier"}]} =
             Actor.get_profile(client(), %{"actor" => "not an identifier!"})
  end

  test "param constraints are validated" do
    # feed.getAuthorFeed limit: minimum 1, maximum 100
    assert {:error, [{"limit", "must be >= 1"}]} =
             Feed.get_author_feed(client(), %{"actor" => "alice.bsky.social", "limit" => 0})

    assert {:error, [{"limit", "must be <= 100"}]} =
             Feed.get_author_feed(client(), %{"actor" => "alice.bsky.social", "limit" => 101})
  end

  test "procedure sends the body as JSON" do
    assert {:ok, _} = Graph.mute_actor(client(), %{"actor" => "did:plc:abcdefgh"})

    assert_received {:post, url, json}
    assert url == "https://public.api.bsky.app/xrpc/app.bsky.graph.muteActor"
    assert json == %{"actor" => "did:plc:abcdefgh"}
  end

  test "procedure with query params puts them in the URL" do
    # app.bsky.video.uploadPart sends the blob in the body, the upload id in
    # the query string
    assert {:ok, _} =
             Video.upload_part(client(), %{"jobId" => "abc", "partNumber" => 1}, <<1, 2, 3>>)

    assert_received {:post, url, body}

    assert url ==
             "https://public.api.bsky.app/xrpc/app.bsky.video.uploadPart?jobId=abc&partNumber=1"

    assert body == <<1, 2, 3>>
  end

  test "zero-param procedure takes only a body" do
    assert {:ok, _} = Actor.put_preferences(client(), %{"preferences" => []})

    assert_received {:post, url, json}
    assert url == "https://public.api.bsky.app/xrpc/app.bsky.actor.putPreferences"
    assert json == %{"preferences" => []}
  end

  test "procedure enforces required query params" do
    assert {:error, errors} = Video.upload_part(client(), %{"partNumber" => 1}, <<>>)
    assert {"jobId", "is required"} in errors
    refute_received {:post, _, _}
  end
end
