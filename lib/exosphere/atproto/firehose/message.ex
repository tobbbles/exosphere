defmodule Exosphere.ATProto.Firehose.Message do
  @moduledoc """
  Parse firehose message payloads into structured events.

  Message types from `com.atproto.sync.subscribeRepos`:
  - `#commit` - Repository commit with record operations
  - `#sync` - Asserts the current repository state (commit + CAR blocks)
  - `#identity` - Identity update (DID document and/or handle change)
  - `#account` - Account hosting status change (active / takendown / suspended /
    deleted / deactivated)
  - `#info` - Informational message

  The following event types are **deprecated** by the current sync spec and
  retained only for backwards compatibility with older relays:

  - `#handle` - Handle change (superseded by `#identity`)
  - `#tombstone` - Repository deletion (superseded by `#account`)
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
          prev_data: CID.t() | nil,
          ops: [operation()],
          blocks: binary(),
          time: String.t()
        }

  @type operation :: %{
          action: :create | :update | :delete,
          path: String.t(),
          cid: CID.t() | nil,
          prev: CID.t() | nil
        }

  @type sync :: %{
          type: :sync,
          seq: integer(),
          did: String.t(),
          rev: String.t() | nil,
          blocks: binary(),
          time: String.t()
        }

  @type identity :: %{
          type: :identity,
          seq: integer(),
          did: String.t(),
          handle: String.t() | nil,
          time: String.t()
        }

  @type account :: %{
          type: :account,
          seq: integer(),
          did: String.t(),
          active: boolean(),
          status: String.t() | nil,
          time: String.t()
        }

  @type handle :: %{
          type: :handle,
          seq: integer(),
          did: String.t(),
          handle: String.t(),
          time: String.t()
        }

  @type message :: commit() | sync() | identity() | account() | handle() | map()

  @doc """
  Decode a message payload based on its type.
  """
  @spec decode(String.t(), map()) :: {:ok, message()}
  def decode("#commit", payload), do: decode_commit(payload)

  def decode("#sync", payload) do
    {:ok,
     %{
       type: :sync,
       seq: Map.get(payload, "seq"),
       did: Map.get(payload, "did"),
       rev: Map.get(payload, "rev"),
       blocks: Map.get(payload, "blocks", <<>>),
       time: Map.get(payload, "time")
     }}
  end

  def decode("#identity", payload) do
    {:ok,
     %{
       type: :identity,
       seq: Map.get(payload, "seq"),
       did: Map.get(payload, "did"),
       handle: Map.get(payload, "handle"),
       time: Map.get(payload, "time")
     }}
  end

  def decode("#account", payload) do
    {:ok,
     %{
       type: :account,
       seq: Map.get(payload, "seq"),
       did: Map.get(payload, "did"),
       active: Map.get(payload, "active"),
       status: Map.get(payload, "status"),
       time: Map.get(payload, "time")
     }}
  end

  # Deprecated: superseded by #identity. Retained for older relays.
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

  # Deprecated: superseded by #account. Retained for older relays.
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

    {:ok,
     %{
       type: :commit,
       seq: Map.get(payload, "seq"),
       repo: Map.get(payload, "repo"),
       commit: as_cid(Map.get(payload, "commit")),
       rev: Map.get(payload, "rev"),
       since: Map.get(payload, "since"),
       prev_data: as_cid(Map.get(payload, "prevData")),
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

    %{
      action: action,
      path: Map.get(op, "path"),
      cid: as_cid(Map.get(op, "cid")),
      prev: as_cid(Map.get(op, "prev"))
    }
  end

  defp decode_operation(op), do: op

  defp as_cid(%CID{} = cid), do: cid
  defp as_cid(_), do: nil

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
          |> Enum.flat_map(fn op ->
            case split_path(op.path) do
              {:ok, collection, rkey} ->
                [
                  %{
                    collection: collection,
                    rkey: rkey,
                    cid: op.cid,
                    record: CAR.get_block(block_map, op.cid)
                  }
                ]

              :error ->
                Logger.debug(
                  "[Firehose.Message] dropping op with malformed path: #{inspect(op.path)}"
                )

                []
            end
          end)

        {:ok, records}

      {:error, reason} ->
        Logger.debug(
          "[Firehose.Message] CAR decode failed: #{inspect(reason)}, falling back to metadata only"
        )

        records =
          ops
          |> Enum.filter(&(&1.action in [:create, :update]))
          |> Enum.flat_map(fn op ->
            case split_path(op.path) do
              {:ok, collection, rkey} ->
                [%{collection: collection, rkey: rkey, cid: op.cid, record: nil}]

              :error ->
                Logger.debug(
                  "[Firehose.Message] dropping op with malformed path: #{inspect(op.path)}"
                )

                []
            end
          end)

        {:ok, records}
    end
  end

  def extract_records(_), do: {:ok, []}

  # Split an op path into {collection, rkey}. Returns :error for nil or paths
  # without a `/` separator (which are not valid Exosphere.ATProto record paths).
  defp split_path(path) when is_binary(path) do
    case String.split(path, "/", parts: 2) do
      [collection, rkey] when collection != "" and rkey != "" -> {:ok, collection, rkey}
      _ -> :error
    end
  end

  defp split_path(_), do: :error

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
