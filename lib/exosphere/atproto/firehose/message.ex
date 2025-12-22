defmodule Exosphere.ATProto.Firehose.Message do
  @moduledoc """
  Parse firehose message payloads into structured events.

  Message types from `com.atproto.sync.subscribeRepos`:
  - `#commit` - Repository commit with record operations
  - `#identity` - Identity update
  - `#handle` - Handle change
  - `#tombstone` - Repository deletion
  - `#info` - Informational message
  """

  alias Exosphere.ATProto.CAR
  alias Exosphere.ATProto.CID

  require Logger

  @type commit :: %{
          type: :commit,
          seq: integer(),
          repo: String.t(),
          commit: CID.t(),
          rev: String.t(),
          since: String.t() | nil,
          ops: [operation()],
          blocks: binary(),
          time: String.t()
        }

  @type operation :: %{
          action: :create | :update | :delete,
          path: String.t(),
          cid: CID.t() | nil
        }

  @type identity :: %{
          type: :identity,
          seq: integer(),
          did: String.t(),
          time: String.t()
        }

  @type handle :: %{
          type: :handle,
          seq: integer(),
          did: String.t(),
          handle: String.t(),
          time: String.t()
        }

  @type message :: commit() | identity() | handle() | map()

  @doc """
  Decode a message payload based on its type.
  """
  @spec decode(String.t(), map()) :: {:ok, message()}
  def decode("#commit", payload), do: decode_commit(payload)

  def decode("#identity", payload) do
    {:ok,
     %{
       type: :identity,
       seq: Map.get(payload, "seq"),
       did: Map.get(payload, "did"),
       time: Map.get(payload, "time")
     }}
  end

  def decode("#handle", payload) do
    {:ok,
     %{
       type: :handle,
       seq: Map.get(payload, "seq"),
       did: Map.get(payload, "did"),
       handle: Map.get(payload, "handle"),
       time: Map.get(payload, "time")
     }}
  end

  def decode("#tombstone", payload) do
    {:ok,
     %{
       type: :tombstone,
       seq: Map.get(payload, "seq"),
       did: Map.get(payload, "did"),
       time: Map.get(payload, "time")
     }}
  end

  def decode("#info", payload) do
    {:ok,
     %{
       type: :info,
       name: Map.get(payload, "name"),
       message: Map.get(payload, "message")
     }}
  end

  def decode(type, payload), do: {:ok, Map.put(payload, :type, type)}

  defp decode_commit(payload) do
    ops =
      payload
      |> Map.get("ops", [])
      |> Enum.map(&decode_operation/1)

    commit_cid =
      case Map.get(payload, "commit") do
        %CID{} = cid -> cid
        _ -> nil
      end

    {:ok,
     %{
       type: :commit,
       seq: Map.get(payload, "seq"),
       repo: Map.get(payload, "repo"),
       commit: commit_cid,
       rev: Map.get(payload, "rev"),
       since: Map.get(payload, "since"),
       ops: ops,
       blocks: Map.get(payload, "blocks", <<>>),
       time: Map.get(payload, "time")
     }}
  end

  defp decode_operation(op) when is_map(op) do
    action =
      case Map.get(op, "action") do
        "create" -> :create
        "update" -> :update
        "delete" -> :delete
        other -> other
      end

    cid =
      case Map.get(op, "cid") do
        %CID{} = c -> c
        _ -> nil
      end

    %{
      action: action,
      path: Map.get(op, "path"),
      cid: cid
    }
  end

  defp decode_operation(op), do: op

  @doc """
  Extract records from a commit's CAR blocks.

  Parses the embedded CAR file to extract the actual record data.
  Returns a list of records with their collection, rkey, cid, and parsed record data.
  """
  @spec extract_records(commit()) :: {:ok, [map()]} | {:error, term()}
  def extract_records(%{blocks: blocks, ops: ops})
      when is_binary(blocks) and byte_size(blocks) > 0 do
    case CAR.decode(blocks) do
      {:ok, block_map} ->
        records =
          ops
          |> Enum.filter(&(&1.action in [:create, :update]))
          |> Enum.map(fn op ->
            [collection, rkey] = String.split(op.path, "/", parts: 2)

            %{
              collection: collection,
              rkey: rkey,
              cid: op.cid,
              record: CAR.get_block(block_map, op.cid)
            }
          end)

        {:ok, records}

      {:error, reason} ->
        Logger.debug(
          "[Firehose.Message] CAR decode failed: #{inspect(reason)}, falling back to metadata only"
        )

        records =
          ops
          |> Enum.filter(&(&1.action in [:create, :update]))
          |> Enum.map(fn op ->
            [collection, rkey] = String.split(op.path, "/", parts: 2)
            %{collection: collection, rkey: rkey, cid: op.cid, record: nil}
          end)

        {:ok, records}
    end
  end

  def extract_records(_), do: {:ok, []}

  @doc """
  Check if a commit contains operations for a specific collection.
  """
  @spec has_collection?(commit(), String.t()) :: boolean()
  def has_collection?(%{ops: ops}, collection) do
    Enum.any?(ops, fn op ->
      String.starts_with?(op.path || "", collection <> "/")
    end)
  end

  @doc """
  Filter operations by collection prefix.
  """
  @spec filter_by_collection(commit(), String.t()) :: [operation()]
  def filter_by_collection(%{ops: ops}, collection) do
    prefix = collection <> "/"
    Enum.filter(ops, &String.starts_with?(&1.path || "", prefix))
  end
end
