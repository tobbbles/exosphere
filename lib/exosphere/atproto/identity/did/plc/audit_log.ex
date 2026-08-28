defmodule Exosphere.ATProto.Identity.DID.PLC.AuditLog do
  @moduledoc """
  Validation of a did:plc audit log — the operation history the directory
  serves from `/:did/log/audit`.

  A log is a chain, not a list. Each operation names its predecessor by CID,
  the first derives the DID from its own bytes, and every operation is signed
  by one of the rotation keys its *predecessor* declared. Validating a log
  means walking that chain and checking each link.

  ## Nullification

  Rotation keys are ordered by descending authority, and a higher-authority
  key may **fork** the log from an earlier point, nullifying the operations
  it displaces. Two rules bound that power:

  - the forking operation must be signed by a **strictly** higher-authority
    key than the one that signed the first operation it nullifies; and
  - it must land within **72 hours** of that operation — inclusive, as
    `log_nullification_at_exactly_72h.json` pins down.

  Nullified operations stay in the log, flagged; they simply stop being part
  of the active chain, and nothing may build on them.

  ## Tombstones

  A `plc_tombstone` permanently deactivates the DID. Nothing may follow one —
  though a tombstone may itself be nullified, which is what
  `log_nullified_tombstone.json` covers.

  ## Why validation is two passes

  Signatures and chaining are checked for *every* operation; the shape rules
  (`rotationKeys` of 1–5, no duplicates, and so on) are checked only for
  operations that survive on the **active** chain.

  That split is not fussiness — it is what the corpus requires.
  `log_nullification.json` is a **valid** log whose middle operation carries
  `rotationKeys: []`: someone emptied their rotation keys, locking the
  identity, and a higher-authority key forked it away inside the recovery
  window. That is precisely the situation the window exists for, so the log
  is valid even though a displaced operation in it is not something we would
  ever emit. `log_empty_rotation_keys.json` is the same operation left
  standing on the active chain, and is **invalid**.

  (The directory has historically accepted operations that do not satisfy its
  own rules — see did-method-plc issue #109 — so "the directory stored it"
  is not evidence of validity.)

  ## Strictness vs the directory

  Shape rules follow the *spec*, which in places is stricter than what the
  production directory actually enforces: the spec allows at most 5 rotation
  keys while the directory accepts up to 10 (`MAX_ROTATION_ENTRIES` in its
  `constraints.ts`), and the spec's 7,500-byte operation cap is enforced at
  4,000. A legitimate directory-stored log can therefore fail validation
  here. That is deliberate — this module validates what an operation
  *should* be, not everything the directory has ever admitted — but callers
  screening arbitrary directory logs should know the divergence exists.

  ## Malformed input

  Entries are validated before they are trusted: `cid` must be present (and
  is recomputed from the operation bytes — a log is a content-addressed
  chain, so a reported CID that does not match its own operation is
  malformed however well it links), `operation` must be a map, every
  entry's `did` must agree with the DID the genesis operation derives, and
  timestamps must be strictly increasing along the chain — the reference
  implementation enforces the same.
  """

  alias Exosphere.ATProto.Identity.DID.PLC.Operation
  alias Exosphere.ATProto.Identity.DID.PLC.Signer

  # Inclusive: an operation landing at exactly 72h still nullifies.
  @recovery_window_seconds 72 * 60 * 60

  @type entry :: %{required(String.t()) => term()}

  @doc """
  Validate a complete audit log.

  Returns `{:ok, nullified_cids}` — the set of operation CIDs the log's own
  rules nullify — or `{:error, reason}`.

  The returned set is what lets a caller cross-check the directory's own
  `nullified` flags rather than trusting them.
  """
  @spec validate([entry()]) :: {:ok, MapSet.t(String.t())} | {:error, term()}
  def validate([]), do: {:error, :empty_log}

  def validate(entries) when is_list(entries) do
    # The first entry is validated before anything dereferences it; the rest
    # are checked inside the walk.
    with :ok <- check_entry(hd(entries), %{}),
         :ok <- validate_genesis(hd(entries)),
         {:ok, did} <- Signer.derive_did(hd(entries)["operation"]),
         :ok <- check_entry_dids(entries, did),
         {:ok, nullified} <- walk(entries, %{}, nil, MapSet.new()),
         :ok <- validate_active_shapes(entries, nullified) do
      {:ok, nullified}
    end
  end

  # Pass two: shape rules apply only to operations still standing.
  defp validate_active_shapes(entries, nullified) do
    Enum.reduce_while(entries, :ok, fn entry, :ok ->
      if MapSet.member?(nullified, entry["cid"]) do
        {:cont, :ok}
      else
        case Operation.validate(entry["operation"]) do
          :ok -> {:cont, :ok}
          {:error, reason} -> {:halt, {:error, {reason, entry["cid"]}}}
        end
      end
    end)
  end

  @doc """
  Validate a log and check the computed nullification against the flags the
  directory reported, so a disagreement is an error rather than a silent
  divergence.
  """
  @spec validate_against_flags([entry()]) :: :ok | {:error, term()}
  def validate_against_flags(entries) do
    case validate(entries) do
      {:ok, nullified} ->
        reported =
          entries
          |> Enum.filter(&Map.get(&1, "nullified", false))
          |> MapSet.new(& &1["cid"])

        if MapSet.equal?(nullified, reported) do
          :ok
        else
          {:error,
           {:nullification_mismatch,
            computed: MapSet.to_list(nullified), reported: MapSet.to_list(reported)}}
        end

      error ->
        error
    end
  end

  # -- the walk --------------------------------------------------------------

  # `seen` maps cid -> %{entry, signer_index}; `head` is the CID of the
  # current active tip.
  defp walk([], _seen, _head, nullified), do: {:ok, nullified}

  defp walk([entry | rest], seen, head, nullified) do
    with :ok <- check_entry(entry, seen),
         :ok <- check_cid(entry),
         {:ok, signer_index, nullified} <- link(entry, seen, head, nullified) do
      seen = Map.put(seen, entry["cid"], %{entry: entry, signer_index: signer_index})
      walk(rest, seen, entry["cid"], nullified)
    end
  end

  # Malformed input is an error, not a crash: log entries are untrusted wire
  # data. The directory never repeats a CID, so a repeat is malformed input.
  defp check_entry(entry, seen) do
    cond do
      not is_map(entry) -> {:error, {:invalid_entry, :not_a_map}}
      not is_binary(entry["cid"]) -> {:error, {:invalid_entry, :missing_cid}}
      not is_map(entry["operation"]) -> {:error, {:invalid_entry, :missing_operation}}
      Map.has_key?(seen, entry["cid"]) -> {:error, {:duplicate_cid, entry["cid"]}}
      true -> :ok
    end
  end

  # The reported CID is recomputed from the operation bytes and must agree.
  # As well as parity with the reference implementation, this pins `seen` to
  # content-addressed keys an attacker cannot choose freely.
  defp check_cid(entry) do
    case Signer.cid(entry["operation"]) do
      {:ok, cid} ->
        if cid == entry["cid"] do
          :ok
        else
          {:error, {:cid_mismatch, expected: cid, got: entry["cid"]}}
        end

      error ->
        error
    end
  end

  # Genesis: self-signed by one of its own rotation keys.
  defp link(entry, seen, _head, nullified) when map_size(seen) == 0 do
    op = entry["operation"]

    case Signer.verify_with_keys(op, Operation.rotation_keys(op)) do
      {:ok, index} -> {:ok, index, nullified}
      {:error, _} -> {:error, {:invalid_signature, entry["cid"]}}
    end
  end

  defp link(entry, seen, head, nullified) do
    op = entry["operation"]

    case Map.get(op, "prev") do
      # A null `prev` this deep in the log is a second genesis, not a lookup
      # miss — report it as what it is.
      nil ->
        {:error, {:unexpected_genesis, entry["cid"]}}

      prev ->
        case Map.get(seen, prev) do
          nil ->
            {:error, {:unknown_prev, prev}}

          %{entry: prev_entry} ->
            cond do
              MapSet.member?(nullified, prev) ->
                {:error, {:builds_on_nullified, entry["cid"]}}

              Operation.tombstone?(prev_entry["operation"]) ->
                {:error, {:builds_on_tombstone, entry["cid"]}}

              true ->
                verify_link(entry, prev, prev_entry, seen, head, nullified)
            end
        end
    end
  end

  defp verify_link(entry, prev, prev_entry, seen, head, nullified) do
    op = entry["operation"]
    keys = Operation.rotation_keys(prev_entry["operation"])

    case Signer.verify_with_keys(op, keys) do
      {:error, _} ->
        {:error, {:invalid_signature, entry["cid"]}}

      {:ok, index} ->
        # Timestamps are server-assigned and strictly ordered: against the
        # predecessor for an extension, against the head for a fork — the
        # reference implementation enforces the same.
        anchor = if prev == head, do: prev_entry, else: Map.fetch!(seen, head).entry

        with :ok <- check_chronology(entry, anchor) do
          if prev == head do
            {:ok, index, nullified}
          else
            fork(entry, prev, index, seen, head, nullified)
          end
        end
    end
  end

  # A fork: everything from prev's successor through the current head is
  # displaced. Permitted only by a strictly higher-authority key, and only
  # within the recovery window of the first operation displaced.
  defp fork(entry, prev, index, seen, head, nullified) do
    displaced = displaced_chain(seen, head, prev, nullified, [])

    case displaced do
      [] ->
        {:ok, index, nullified}

      [first | _] ->
        first_meta = Map.fetch!(seen, first)

        with :ok <- check_authority(index, first_meta.signer_index, entry),
             :ok <- check_window(entry, first_meta.entry) do
          {:ok, index, Enum.into(displaced, nullified)}
        end
    end
  end

  # Walk back from head to prev, collecting the CIDs in between (oldest first).
  defp displaced_chain(_seen, cursor, prev, _nullified, acc) when cursor == prev, do: acc

  defp displaced_chain(seen, cursor, prev, nullified, acc) do
    case Map.get(seen, cursor) do
      nil ->
        acc

      %{entry: entry} ->
        acc = if MapSet.member?(nullified, cursor), do: acc, else: [cursor | acc]
        next = Map.get(entry["operation"], "prev")
        displaced_chain(seen, next, prev, nullified, acc)
    end
  end

  defp check_authority(index, displaced_index, entry) do
    if index < displaced_index do
      :ok
    else
      {:error, {:insufficient_authority, entry["cid"]}}
    end
  end

  defp check_window(entry, displaced_entry) do
    with {:ok, at} <- timestamp(entry),
         {:ok, displaced_at} <- timestamp(displaced_entry) do
      if DateTime.diff(at, displaced_at, :second) <= @recovery_window_seconds do
        :ok
      else
        {:error, {:recovery_window_expired, entry["cid"]}}
      end
    end
  end

  defp timestamp(entry) do
    case DateTime.from_iso8601(to_string(entry["createdAt"])) do
      {:ok, dt, _offset} -> {:ok, dt}
      {:error, reason} -> {:error, {:invalid_timestamp, reason}}
    end
  end

  defp check_chronology(entry, anchor_entry) do
    with {:ok, at} <- timestamp(entry),
         {:ok, anchor_at} <- timestamp(anchor_entry) do
      if DateTime.compare(at, anchor_at) == :gt do
        :ok
      else
        {:error, {:invalid_timestamp_order, entry["cid"]}}
      end
    end
  end

  defp validate_genesis(entry) do
    if is_nil(Map.get(entry["operation"], "prev")) do
      :ok
    else
      {:error, :first_operation_not_genesis}
    end
  end

  # Every entry in a log belongs to the DID its genesis derives. A missing
  # `did` is tolerated (it is redundant data), a disagreeing one is not.
  defp check_entry_dids(entries, did) do
    Enum.reduce_while(entries, :ok, fn entry, :ok ->
      case Map.get(entry, "did") do
        nil -> {:cont, :ok}
        ^did -> {:cont, :ok}
        other -> {:halt, {:error, {:did_mismatch, expected: did, got: other}}}
      end
    end)
  end
end
