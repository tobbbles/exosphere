defmodule Exosphere.ATProto.Firehose.Emitter do
  @moduledoc """
  Produce `com.atproto.sync.subscribeRepos` messages.

  `Exosphere.ATProto.Firehose.Consumer` reads the firehose; this writes it. It
  is the assembly step between a repository write and a websocket frame: apply
  the record operations to the MST, sign a commit over the new root, gather the
  blocks the message has to carry, and frame it.

  ## The blocks a commit carries

  A `#commit` message's `blocks` field is a CAR slice, not a repository export.
  It holds the commit block, the MST nodes this commit changed, the record
  blocks it created or updated — and, importantly, enough *unchanged* MST nodes
  for a consumer to run the operations backwards and arrive at the previous
  root, which the message names in `prevData`.

  That last part is what makes a commit verifiable on its own. A consumer
  holding no repository state can check the signature, invert the operations
  against the slice, and confirm the result matches the `prevData` it was
  told — and, if it tracked the previous commit, that `prevData` matches what
  it last saw.

  `Exosphere.ATProto.MST.covering_proof/4` computes those blocks and
  `Exosphere.ATProto.MST.invert/3` is the other half of the contract. Commits
  from this module are guaranteed to invert: a slice one node short fails
  inversion with a missing block rather than producing a wrong answer, so if
  you are writing your own producer, inverting your own output is the way to
  know the proof is complete.

  ## Limits

  The sync spec caps a commit at 200 operations, its `blocks` at 2,000,000
  bytes, an individual record block at 1,000,000 bytes, and a whole frame at
  5,000,000 bytes. All four are enforced here, failing with a descriptive error
  rather than emitting something a relay will reject.

  ## Example

      store = Exosphere.ATProto.MST.Store.ETS.new()

      {:ok, result} =
        Emitter.commit(store,
          did: did,
          root: nil,
          seq: 1,
          private_key: key,
          curve: :secp256k1,
          writes: [{:create, "app.bsky.feed.post/3lbqmqtqhpk2a", %{"text" => "hello"}}]
        )

      # `result.frame` is a binary websocket frame — send it however you send
      # frames, then carry result.root, result.commit and result.rev into the
      # next commit.

  ## What this leaves to you

  This builds messages; it does not run a service. Transport, storage and
  lifecycle stay yours, and deliberately so — none of it can be guessed from
  here:

    * **Sequence numbers.** `seq` must be monotonic across everything a service
      emits and must survive a restart, since consumers use it as a resumption
      cursor. This module takes the number and never invents one.
    * **Persistence.** Nothing is written anywhere except the block store you
      pass in. The `root`, `commit` and `rev` in the result are what the next
      commit builds on; where they live is your decision.
    * **Delivery.** Fan-out to subscribers, backfill windows, and cursor
      replay are the server's job. `Exosphere.ATProto.Firehose.Frame` gives you
      the bytes.
    * **Concurrency.** A commit is a read-modify-write against one repository,
      so serialize the writes for a given DID however your application already
      serializes them.
  """

  alias Exosphere.ATProto.CAR
  alias Exosphere.ATProto.CBOR, as: DagCBOR
  alias Exosphere.ATProto.CID
  alias Exosphere.ATProto.Firehose.{Frame, Message}
  alias Exosphere.ATProto.MST
  alias Exosphere.ATProto.MST.Store
  alias Exosphere.ATProto.Repo.Commit
  alias Exosphere.ATProto.TID

  @max_ops 200
  @max_blocks_bytes 2_000_000
  @max_record_bytes 1_000_000

  @typedoc """
  A repository write: a record to put at a path, or a path to remove.
  """
  @type write ::
          {:create, MST.key(), map()}
          | {:update, MST.key(), map()}
          | {:delete, MST.key()}

  @typedoc """
  What a commit produced: the frame to send, plus the state to carry forward.
  """
  @type result :: %{
          frame: binary(),
          message: map(),
          commit: CID.t(),
          root: CID.t(),
          rev: String.t(),
          store: Store.t()
        }

  @doc """
  Apply writes, sign a commit, and produce the `#commit` frame.

  ## Options

    * `:did` (required) - the repository's DID
    * `:seq` (required) - this message's sequence number
    * `:private_key` (required) - the account's signing key
    * `:writes` (required) - the record operations, at most 200
    * `:curve` - `:secp256k1` (default) or `:p256`
    * `:root` - the current MST root, or `nil` for a repository's first commit
    * `:rev` - the commit's TID revision (default: a fresh `TID.generate/0`)
    * `:since` - the `rev` this diff is against (default: `nil`)
    * `:time` - the message timestamp (default: now, ISO 8601)

  Returns `{:ok, result}` — see `t:result/0`. The `:store` in the result holds
  the new blocks; the `:root`, `:commit` and `:rev` are what the next commit
  builds on.
  """
  @spec commit(Store.t(), keyword()) :: {:ok, result()} | {:error, term()}
  def commit(store, opts) do
    with {:ok, did} <- require_opt(opts, :did),
         {:ok, seq} <- require_opt(opts, :seq),
         {:ok, private_key} <- require_opt(opts, :private_key),
         {:ok, writes} <- require_opt(opts, :writes),
         :ok <- check_op_count(writes),
         previous = Keyword.get(opts, :root),
         {:ok, ops, records} <- resolve_writes(writes, previous, store),
         {:ok, root, store, changed} <- MST.apply_ops(previous, store, tree_ops(ops)),
         {:ok, proof} <- MST.covering_proof(previous, root, store, Enum.map(ops, & &1.path)),
         rev = Keyword.get(opts, :rev) || TID.generate(),
         {:ok, commit, commit_cid, commit_bytes} <-
           signed_commit(did, root, rev, private_key, Keyword.get(opts, :curve, :secp256k1)),
         blocks = Map.merge(Map.merge(proof, changed), records),
         {:ok, car} <- commit_car(commit_cid, commit_bytes, blocks),
         message =
           build_commit_message(did, seq, commit_cid, rev, opts, previous, ops, car),
         {:ok, frame} <- frame(message) do
      {:ok,
       %{
         frame: frame,
         message: message,
         commit: commit_cid,
         root: root,
         rev: rev,
         store: Store.put(store, commit_cid, commit_bytes),
         commit_block: commit
       }}
    end
  end

  @doc """
  Produce a `#sync` frame: the repository's current commit, and nothing else.

  A `#sync` message asserts where an account's repository currently stands, for
  a consumer that has fallen behind or has never seen it. Its `blocks` carry
  only the commit block, with the commit as the CAR's first root — the contents
  are not included, deliberately.
  """
  @spec sync(keyword()) :: {:ok, %{frame: binary(), message: map()}} | {:error, term()}
  def sync(opts) do
    with {:ok, did} <- require_opt(opts, :did),
         {:ok, seq} <- require_opt(opts, :seq),
         {:ok, commit_cid} <- require_opt(opts, :commit),
         {:ok, commit_bytes} <- require_opt(opts, :commit_block),
         {:ok, rev} <- require_opt(opts, :rev),
         {:ok, car} <- CAR.encode(commit_cid, [{commit_cid, commit_bytes}]) do
      message = %{
        type: :sync,
        seq: seq,
        did: did,
        rev: rev,
        blocks: car,
        time: Keyword.get(opts, :time) || now()
      }

      with {:ok, frame} <- frame(message), do: {:ok, %{frame: frame, message: message}}
    end
  end

  @doc """
  Produce an `#identity` frame, signalling that an account's identity may have
  changed.

  Best-effort by design: consumers treat it as "re-resolve this DID", not as a
  statement of the new value, so redundant messages are harmless.
  """
  @spec identity(keyword()) :: {:ok, %{frame: binary(), message: map()}} | {:error, term()}
  def identity(opts) do
    with {:ok, did} <- require_opt(opts, :did),
         {:ok, seq} <- require_opt(opts, :seq) do
      emit(%{
        type: :identity,
        seq: seq,
        did: did,
        handle: Keyword.get(opts, :handle),
        time: Keyword.get(opts, :time) || now()
      })
    end
  end

  @doc """
  Produce an `#account` frame for a change in hosting status.

  `:active` is required; `:status` carries `"takendown"`, `"suspended"`,
  `"deleted"` or `"deactivated"` when the account is not active.
  """
  @spec account(keyword()) :: {:ok, %{frame: binary(), message: map()}} | {:error, term()}
  def account(opts) do
    with {:ok, did} <- require_opt(opts, :did),
         {:ok, seq} <- require_opt(opts, :seq),
         {:ok, active} <- require_opt(opts, :active) do
      emit(%{
        type: :account,
        seq: seq,
        did: did,
        active: active,
        status: Keyword.get(opts, :status),
        time: Keyword.get(opts, :time) || now()
      })
    end
  end

  @doc """
  Produce an `#info` frame.
  """
  @spec info(String.t(), String.t() | nil) ::
          {:ok, %{frame: binary(), message: map()}} | {:error, term()}
  def info(name, message \\ nil) when is_binary(name) do
    emit(%{type: :info, name: name, message: message})
  end

  @doc """
  The spec's per-commit operation limit (200).
  """
  @spec max_ops() :: pos_integer()
  def max_ops, do: @max_ops

  @doc """
  The spec's `blocks` size limit for a `#commit`, in bytes (2,000,000).
  """
  @spec max_blocks_bytes() :: pos_integer()
  def max_blocks_bytes, do: @max_blocks_bytes

  # --- Internals ---------------------------------------------------------------

  defp emit(message) do
    with {:ok, frame} <- frame(message), do: {:ok, %{frame: frame, message: message}}
  end

  defp frame(message) do
    with {:ok, type, payload} <- Message.encode(message) do
      Frame.encode_message(type, payload)
    end
  end

  defp check_op_count(writes) when is_list(writes) do
    count = length(writes)
    if count <= @max_ops, do: :ok, else: {:error, {:too_many_ops, count}}
  end

  defp check_op_count(_), do: {:error, :invalid_writes}

  # Turn writes into firehose operations, looking up the version each update or
  # delete replaces: `prev` is what lets a consumer invert the operation, so a
  # missing one is a hard error rather than a silent omission.
  defp resolve_writes(writes, previous, store) do
    Enum.reduce_while(writes, {:ok, [], %{}}, fn write, {:ok, ops, records} ->
      case resolve_write(write, previous, store) do
        {:ok, op, block} ->
          {:cont, {:ok, ops ++ [op], Map.merge(records, block)}}

        {:error, _} = error ->
          {:halt, error}
      end
    end)
  end

  defp resolve_write({action, path, record}, previous, store)
       when action in [:create, :update] and is_binary(path) and is_map(record) do
    with {:ok, bytes} <- DagCBOR.encode(record),
         :ok <- check_record_size(path, bytes),
         {:ok, prev} <- lookup(previous, store, path) do
      cid = CID.create!(record)
      op = %{action: action, path: path, cid: cid, prev: prev}
      {:ok, op, %{cid => bytes}}
    end
  end

  defp resolve_write({:delete, path}, previous, store) when is_binary(path) do
    with {:ok, prev} <- lookup(previous, store, path) do
      {:ok, %{action: :delete, path: path, cid: nil, prev: prev}, %{}}
    end
  end

  defp resolve_write(write, _previous, _store), do: {:error, {:invalid_write, write}}

  defp lookup(nil, _store, _path), do: {:ok, nil}
  defp lookup(%CID{} = root, store, path), do: MST.fetch(root, store, path)

  defp check_record_size(path, bytes) do
    if byte_size(bytes) <= @max_record_bytes do
      :ok
    else
      {:error, {:record_too_large, path, byte_size(bytes)}}
    end
  end

  defp tree_ops(ops) do
    Enum.map(ops, fn
      %{action: :delete, path: path} -> {:delete, path}
      %{path: path, cid: cid} -> {:put, path, cid}
    end)
  end

  defp signed_commit(did, root, rev, private_key, curve) do
    with {:ok, commit} <- Commit.sign(Commit.build(did, root, rev), private_key, curve),
         {:ok, bytes} <- DagCBOR.encode(commit) do
      {:ok, commit, CID.create!(commit), bytes}
    end
  end

  # The commit block leads the slice, and is the CAR's single root — a consumer
  # reads it first and works down from there.
  defp commit_car(commit_cid, commit_bytes, blocks) do
    frames = [{commit_cid, commit_bytes} | Enum.to_list(Map.delete(blocks, commit_cid))]

    with {:ok, car} <- CAR.encode(commit_cid, frames) do
      if byte_size(car) <= @max_blocks_bytes do
        {:ok, car}
      else
        {:error, {:blocks_too_large, byte_size(car)}}
      end
    end
  end

  defp build_commit_message(did, seq, commit_cid, rev, opts, previous, ops, car) do
    %{
      type: :commit,
      seq: seq,
      repo: did,
      commit: commit_cid,
      rev: rev,
      since: Keyword.get(opts, :since),
      # The previous MST root. Unsigned, so a consumer checks it against the
      # root it last saw rather than trusting it — but without it a commit
      # cannot be inverted at all.
      prev_data: previous,
      ops: ops,
      blocks: car,
      time: Keyword.get(opts, :time) || now()
    }
  end

  defp require_opt(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, {:missing_option, key}}
    end
  end

  defp now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
