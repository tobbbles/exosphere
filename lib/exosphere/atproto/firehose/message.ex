defmodule Exosphere.ATProto.Firehose.Message do
  @moduledoc """
  Parse firehose message payloads into structured events, and build them.

  `decode/2` turns a wire payload into a structured event; `encode/1` turns one
  back into a wire payload, so a producer describes the message it wants in the
  same shape a consumer reads. `Exosphere.ATProto.Firehose.Emitter` sits above
  this and assembles a `#commit` from a repository transition.

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
  alias Exosphere.ATProto.Repo.Commit

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

  # Deprecated: superseded by #account. Retained for older relays.
  @type tombstone :: %{
          type: :tombstone,
          seq: integer(),
          did: String.t(),
          time: String.t()
        }

  @type info :: %{
          type: :info,
          name: String.t() | nil,
          message: String.t() | nil
        }

  # Unknown message headers pass through as raw maps (with `:type` attached),
  # keeping consumers forward-compatible with new relay event types.
  @type message ::
          commit() | sync() | identity() | account() | handle() | tombstone() | info() | map()

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

  @doc """
  Build the wire payload for a message, ready for
  `Exosphere.ATProto.Firehose.Frame.encode_message/2`.

  Takes the same structured shape `decode/2` produces and returns
  `{:ok, type, payload}`, so `decode/2` and `encode/1` round-trip. Bytes fields
  (`blocks`) are tagged as CBOR byte strings; `nil` optional fields are written
  as CBOR null rather than omitted, matching what the reference producer emits.

  ## Examples

      iex> {:ok, "#account", payload} =
      ...>   Exosphere.ATProto.Firehose.Message.encode(%{
      ...>     type: :account, seq: 1, did: "did:plc:abc",
      ...>     active: false, status: "takendown", time: "2026-08-28T00:00:00.000Z"
      ...>   })
      iex> payload["status"]
      "takendown"
  """
  @spec encode(message()) :: {:ok, String.t(), map()} | {:error, term()}
  def encode(%{type: :commit} = message) do
    with {:ok, ops} <- encode_ops(Map.get(message, :ops, [])) do
      payload = %{
        "seq" => Map.get(message, :seq),
        "repo" => Map.get(message, :repo),
        "commit" => Map.get(message, :commit),
        "rev" => Map.get(message, :rev),
        "since" => Map.get(message, :since),
        "blocks" => bytes(Map.get(message, :blocks, <<>>)),
        "ops" => ops,
        "prevData" => Map.get(message, :prev_data),
        # Both deprecated: a producer sets tooBig false and blobs empty.
        "tooBig" => false,
        "blobs" => [],
        "time" => Map.get(message, :time)
      }

      {:ok, "#commit", payload}
    end
  end

  def encode(%{type: :sync} = message) do
    {:ok, "#sync",
     %{
       "seq" => Map.get(message, :seq),
       "did" => Map.get(message, :did),
       "blocks" => bytes(Map.get(message, :blocks, <<>>)),
       "rev" => Map.get(message, :rev),
       "time" => Map.get(message, :time)
     }}
  end

  def encode(%{type: :identity} = message) do
    {:ok, "#identity",
     %{
       "seq" => Map.get(message, :seq),
       "did" => Map.get(message, :did),
       "handle" => Map.get(message, :handle),
       "time" => Map.get(message, :time)
     }}
  end

  def encode(%{type: :account} = message) do
    {:ok, "#account",
     %{
       "seq" => Map.get(message, :seq),
       "did" => Map.get(message, :did),
       "active" => Map.get(message, :active),
       "status" => Map.get(message, :status),
       "time" => Map.get(message, :time)
     }}
  end

  def encode(%{type: :info} = message) do
    {:ok, "#info",
     %{
       "name" => Map.get(message, :name),
       "message" => Map.get(message, :message)
     }}
  end

  def encode(%{type: type}), do: {:error, {:unencodable_message, type}}
  def encode(_), do: {:error, :not_a_message}

  defp encode_ops(ops) when is_list(ops) do
    Enum.reduce_while(ops, {:ok, []}, fn op, {:ok, acc} ->
      case encode_op(op) do
        {:ok, encoded} -> {:cont, {:ok, [encoded | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, encoded} -> {:ok, Enum.reverse(encoded)}
      error -> error
    end
  end

  defp encode_ops(_), do: {:error, :invalid_ops}

  # `prev` is written only for update and delete, where it names the record
  # version being replaced — a create has nothing to point at.
  defp encode_op(%{action: action, path: path} = op)
       when action in [:create, :update, :delete] and is_binary(path) do
    base = %{
      "action" => Atom.to_string(action),
      "path" => path,
      "cid" => Map.get(op, :cid)
    }

    encoded =
      case {action, Map.get(op, :prev)} do
        {:create, _} -> base
        {_, %CID{} = prev} -> Map.put(base, "prev", prev)
        {_, _} -> base
      end

    {:ok, encoded}
  end

  defp encode_op(op), do: {:error, {:invalid_op, op}}

  defp bytes(value) when is_binary(value), do: %CBOR.Tag{tag: :bytes, value: value}
  defp bytes(%CBOR.Tag{tag: :bytes} = tagged), do: tagged

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
  Verify a `#commit` message's blocks against its signed MST root.

  Decodes the embedded CAR, confirms the CAR's root is the commit the message
  points at, and checks the commit's record set against its signed `data`
  root via `Exosphere.ATProto.Repo.Commit.verify_checkout/2`. On success the
  full `path => CID` record set is returned.

  Firehose commit CARs are *incremental*: they only carry the blocks new in
  that commit, so unchanged MST subtrees are referenced but not included.
  This function therefore succeeds only when every referenced node is
  present — typically an initial snapshot commit (no `since`). For
  steady-state verification, maintain the record set across commits and
  rebuild via `MST.build/1` + `Commit.verify_data/2`, or verify a complete
  snapshot with `Exosphere.ATProto.Repo.verify_checkout/3`.

  This checks structure only; authenticate the signer with
  `Exosphere.ATProto.Repo.Commit.verify/3` and the repo's DID document.

  Returns `{:ok, records}`, `{:error, :not_a_commit}` for other message
  types, `{:error, :commit_not_in_blocks}` when the root block is absent,
  `{:error, :root_mismatch}` when the CAR root disagrees with the message's
  commit link, or any error from CAR decoding / `verify_checkout/2` (e.g.
  `{:error, {:missing_block, cid}}` for an incremental CAR).
  """
  @spec verify_commit(commit()) :: {:ok, %{String.t() => CID.t()}} | {:error, term()}
  def verify_commit(%{type: :commit, blocks: blocks, commit: %CID{} = commit_cid})
      when is_binary(blocks) do
    with {:ok, %{roots: roots, blocks: block_map}} <- CAR.decode_full(blocks),
         :ok <- check_root(roots, commit_cid),
         commit when is_map(commit) <- fetch_commit(block_map, commit_cid) do
      Commit.verify_checkout(commit, block_map)
    end
  end

  def verify_commit(%{type: :commit, commit: nil}), do: {:error, :missing_commit_link}
  def verify_commit(_), do: {:error, :not_a_commit}

  defp check_root([root], commit_cid) when root == commit_cid, do: :ok
  defp check_root(_, _), do: {:error, :root_mismatch}

  defp fetch_commit(block_map, commit_cid) do
    case Map.get(block_map, commit_cid) do
      commit when is_map(commit) -> commit
      _ -> {:error, :commit_not_in_blocks}
    end
  end

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
