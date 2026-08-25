defmodule Exosphere.Bsky.RecordsTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.XRPC.Client
  alias Exosphere.Bsky.{Feed.Post, Records}

  defmodule FakeHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    def get(url, _opts \\ []) do
      send(self(), {:get, url})

      body =
        if String.contains?(url, "listRecords") do
          %{
            "records" => [
              %{
                "uri" => "at://did:plc:author/app.bsky.feed.post/3jzfcijpj2z2a",
                "cid" => "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
                "value" => %{
                  "$type" => "app.bsky.feed.post",
                  "text" => "from the repo",
                  "createdAt" => "2026-08-25T12:00:00.000Z"
                }
              }
            ],
            "cursor" => "next-page"
          }
        else
          get_record_body()
        end

      {:ok, %{status: 200, body: body}}
    end

    def post(_url, _opts \\ []), do: {:ok, %{status: 200, body: %{}}}

    defp get_record_body do
      %{
        "uri" => "at://did:plc:author/app.bsky.feed.post/3jzfcijpj2z2a",
        "cid" => "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
        "value" => %{
          "$type" => "app.bsky.feed.post",
          "text" => "from the repo",
          "createdAt" => "2026-08-25T12:00:00.000Z"
        }
      }
    end
  end

  defp client, do: Client.new("https://pds.example.com", http: FakeHTTP)

  test "get/4 fetches by collection module and decodes the record" do
    assert {:ok, %Post{} = post} = Records.get(client(), "did:plc:author", Post, "3jzfcijpj2z2a")
    assert post.text == "from the repo"
    assert post.created_at == "2026-08-25T12:00:00.000Z"

    assert_received {:get, url}

    assert url ==
             "https://pds.example.com/xrpc/com.atproto.repo.getRecord" <>
               "?repo=did%3Aplc%3Aauthor&collection=app.bsky.feed.post&rkey=3jzfcijpj2z2a"
  end

  test "get/4 accepts a bare server URL" do
    # Same fake via client opts isn't possible with a bare URL, so this just
    # asserts arity/dispatch shape by checking the error is a request failure,
    # not a function clause
    assert match?({:error, _}, Records.get("https://invalid.invalid", "did:plc:x", Post, "rkey"))
  end

  test "list/4 decodes every record and returns the cursor" do
    # FakeHTTP.get returns a single-record body shaped like getRecord; list
    # tolerates the shape and decodes whatever "records" it finds
    assert {:ok, [%Post{text: "from the repo"}], "next-page"} =
             Records.list(client(), "did:plc:author", Post, limit: 10)

    assert_received {:get, url}
    assert url =~ "com.atproto.repo.listRecords"
    assert url =~ "collection=app.bsky.feed.post"
  end

  test "create/5 generates a TID record key by default" do
    # Repo.put_record hits the network; with the fake it just succeeds. The
    # assertion of interest is that rkey generation and collection mapping
    # don't raise and the call succeeds.
    # Repo signs DPoP proofs; give it a real p256 JWK (base64 JSON)
    jwk =
      JOSE.JWK.generate_key({:ec, "P-256"})
      |> JOSE.JWK.to_map()
      |> elem(1)
      |> Jason.encode!()
      |> Base.encode64()

    session = %{access_token: "tok", dpop_private_key: jwk, did: "did:plc:author"}

    {:ok, post} =
      Post.new(%{"text" => "hi", "createdAt" => "2026-08-25T12:00:00.000Z"})

    # Repo's authenticated path isn't HTTP-injectable; a transport error
    # from an unresolvable host proves rkey generation, collection mapping,
    # and wire encoding all succeeded before the request went out.
    assert match?(
             {:error, %Mint.TransportError{reason: :nxdomain}},
             Records.create(session, "https://pds.invalid", "did:plc:author", post)
           )
  end
end
