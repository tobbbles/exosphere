defmodule Exosphere.Lexicon.ResolverTest do
  use ExUnit.Case, async: true

  alias Exosphere.Lexicon.{Registry, Resolver}

  defmodule FakeHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    @schema_record %{
      "$type" => "com.atproto.lexicon.schema",
      "lexicon" => 1,
      "id" => "com.example.post",
      "defs" => %{
        "main" => %{
          "type" => "record",
          "key" => "tid",
          "record" => %{
            "type" => "object",
            "required" => ["text"],
            "properties" => %{"text" => %{"type" => "string"}}
          }
        }
      }
    }

    def get(url, _opts \\ []) do
      body =
        cond do
          String.contains?(url, "getRecord") ->
            %{
              "uri" => "at://did:plc:abc/com.atproto.lexicon.schema/com.example.post",
              "value" => @schema_record
            }

          String.contains?(url, "listRecords") ->
            %{
              "records" => [
                %{
                  "uri" => "at://did:plc:abc/com.atproto.lexicon.schema/com.example.post",
                  "value" => @schema_record
                }
              ]
            }

          true ->
            %{}
        end

      {:ok, %{status: 200, body: body}}
    end

    def post(_url, _opts \\ []), do: {:ok, %{status: 200, body: %{}}}
  end

  @opts [http: FakeHTTP]

  test "fetch/4 retrieves and validates a schema record" do
    assert {:ok, schema} =
             Resolver.fetch("https://pds.example.com", "did:plc:abc", "com.example.post", @opts)

    assert schema.id == "com.example.post"

    refute Registry.registered?("com.example.post")
  end

  test "fetch/4 with register: true registers the lexicon" do
    assert {:ok, _} =
             Resolver.fetch(
               "https://pds.example.com",
               "did:plc:abc",
               "com.example.post",
               @opts ++ [register: true]
             )

    assert Registry.registered?("com.example.post")

    assert :ok =
             Registry.validate("com.example.post", %{
               "$type" => "com.example.post",
               "text" => "hi"
             })
  after
    Registry.reset()
  end

  test "list/3 returns every published lexicon" do
    assert {:ok, [schema], %{invalid: []}} =
             Resolver.list("https://pds.example.com", "did:plc:abc", @opts)

    assert schema.id == "com.example.post"
  end

  test "resolve/2 fails cleanly when no DNS TXT record exists" do
    # example.invalid has no _lexicon TXT record; a real DNS query in tests
    # is acceptable here since it asserts a negative result quickly
    assert {:error, _} = Resolver.resolve("invalid.localhost-never-exists.post")
  end
end
