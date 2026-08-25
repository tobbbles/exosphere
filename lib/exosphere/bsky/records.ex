defmodule Exosphere.Bsky.Records do
  @moduledoc """
  Typed repository operations: create, fetch, list, and delete records
  through their generated struct modules.

  The collection NSID and wire encoding come from each struct's generated
  module (`type_id/0` and `to_map/1`), so a `%Exosphere.Bsky.Feed.Post{}`
  knows it belongs in `app.bsky.feed.post`.

  Writes go to the user's PDS (authenticated); reads may go to any server
  hosting the record (e.g. the App View or the PDS itself).

  ## Examples

      {:ok, post} = Exosphere.Bsky.Feed.Post.new(%{text: "Hello!", created_at: DateTime.utc_now() |> DateTime.to_iso8601()})

      {:ok, %{uri: uri, cid: cid}} =
        Exosphere.Bsky.Records.create(session, pds_url, did, post)

      {:ok, %Exosphere.Bsky.Feed.Post{} = post} =
        Exosphere.Bsky.Records.get(pds_url, did, Exosphere.Bsky.Feed.Post, rkey)
  """

  alias Exosphere.ATProto.{Repo, TID, XRPC.Client}

  @doc """
  Create a record from a generated struct.

  The collection is taken from the struct's lexicon type ID. An optional
  `:rkey` overrides the generated one (record schemas with `tid` keys get a
  fresh TID; `self`-keyed records should pass `rkey: "self"`).
  """
  @spec create(map(), String.t(), String.t(), struct(), keyword()) ::
          {:ok, %{uri: String.t(), cid: String.t()}} | {:error, term()}
  def create(session, pds_url, did, record, opts \\ []) do
    collection = collection_of(record)

    with {:ok, rkey} <- rkey_for(collection, opts) do
      Repo.put_record(session, pds_url, did, collection, rkey, to_wire(record))
    end
  end

  @doc """
  Fetch and decode a record by collection module and record key.

  Accepts a server URL or a pre-built `Client` (inject `http:` for testing).
  The module must be a generated schema module (`Exosphere.Bsky.Feed.Post`,
  `Exosphere.Community.Interaction.Like`, ...).
  """
  @spec get(String.t() | Client.t(), String.t(), module(), String.t()) ::
          {:ok, struct()} | {:error, term()}
  def get(server, did, module, rkey) do
    with {:ok, %{"value" => value}} <-
           Client.query(client(server), "com.atproto.repo.getRecord",
             repo: did,
             collection: module.type_id(),
             rkey: rkey
           ) do
      module.from_map(value)
    end
  end

  @doc """
  List records in a collection, decoding each into `module`.

  Returns `{:ok, records, cursor}` where cursor is nil or the next-page
  cursor from the server.
  """
  @spec list(String.t() | Client.t(), String.t(), module(), keyword()) ::
          {:ok, [struct()], cursor :: String.t() | nil} | {:error, term()}
  def list(server, did, module, opts \\ []) do
    params =
      [repo: did, collection: module.type_id()]
      |> Keyword.merge(opts)

    with {:ok, %{"records" => wire_records} = response} <-
           Client.query(client(server), "com.atproto.repo.listRecords", params) do
      records =
        wire_records
        |> Enum.map(&Map.fetch!(&1, "value"))
        |> Enum.flat_map(fn value ->
          case module.from_map(value) do
            {:ok, record} -> [record]
            {:error, _} -> []
          end
        end)

      {:ok, records, response["cursor"]}
    end
  end

  @doc """
  Delete a record by collection module and record key.
  """
  @spec delete(map(), String.t(), String.t(), module(), String.t()) ::
          {:ok, map()} | {:error, term()}
  def delete(session, pds_url, did, module, rkey) do
    Repo.delete_record(session, pds_url, did, module.type_id(), rkey)
  end

  # --- Internals -------------------------------------------------------------------

  defp client(%Client{} = client), do: client
  defp client(url) when is_binary(url), do: Client.new(url)

  defp collection_of(record) do
    module = record.__struct__
    Code.ensure_loaded!(module)

    function_exported?(module, :type_id, 0) ||
      raise ArgumentError, "#{inspect(module)} is not a generated lexicon module"

    module.type_id()
  end

  defp rkey_for(_collection, opts) do
    case Keyword.get(opts, :rkey) do
      nil -> {:ok, TID.generate()}
      rkey -> {:ok, rkey}
    end
  end

  defp to_wire(record) do
    record.__struct__.to_map(record)
  end
end
