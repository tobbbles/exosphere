defmodule Exosphere.ATProto.Spaces.Memberspace do
  @moduledoc """
  The member list of a space governed by `com.atproto.memberspace.policy`
  (proposal 0016, "`memberspace`"; atproto `7992095`), managed on the
  authority's PDS.

  Each entry (`com.atproto.memberspace.defs#member`) carries a `did` and
  required `read` and `write` booleans; `put_members/5` replaces both
  together. The list is not part of the policy object: it persists across
  configuration changes and is discarded when the space migrates to a
  different policy. Calling these on a space under another policy answers
  `PolicyMismatch`.

  Changes are batched (November 12 alpha): `putMembers` takes
  `{space, members: [{did, read, write}]}` and `removeMembers`
  `{space, dids: [did]}`, each up to 100 entries applied in a single commit.
  A DID listed twice in `putMembers` takes its last entry; `removeMembers`
  ignores DIDs that are not members (and leaves them in the writer set).
  Removing a member, or putting one with `write: false`, also removes it
  from the writer set, which the host announces to syncers as a
  `com.atproto.space.defs#repoRemoved`. Under a memberspace with
  `public_write`, a member whose `write` is false is not tracked as a writer.

  OAuth-authenticated as the space authority (`manage=update` for writes,
  `read_self` for `list_members/4`): pass `session:` or `headers:` as for
  `Spaces.Space`. A space credential cannot list members — to make the list
  visible to readers, set the policy's `publish_members`. A caller that is
  not the authority is refused `NotAuthorized`, returned as
  `{:error, :not_authorized}`; a cursor the host cannot read is
  `{:error, :invalid_cursor}`.

  ## Host side

  A space host receiving these calls can shape their input with
  `decode_put_members/1` (validated, deduplicated last-entry-wins) and
  `decode_remove_members/1`, and build `listMembers` entries with
  `member/3`.
  """

  alias Exosphere.ATProto.Identity.DID
  alias Exosphere.ATProto.Spaces.XRPC

  @nsid "com.atproto.memberspace"
  @max_batch 100

  @typedoc """
  A member entry: a map with `:did` (required), `:read` and `:write`
  (booleans, both defaulting to `true`), or a bare DID meaning read and write.
  """
  @type member :: String.t() | %{required(:did) => String.t(), optional(atom()) => boolean()}

  @typedoc "A decoded `com.atproto.memberspace.defs#member`."
  @type access :: %{did: String.t(), read: boolean(), write: boolean()}

  @doc """
  Add members, or replace the access of members already on the list
  (`com.atproto.memberspace.putMembers`), in one commit. `members` is a list
  of 1 to 100 entries (see `t:member/0`); `read: false, write: false` parks a
  member on the list without access. Revoking write access should also drop
  the member from the writer set (the authority's job, per the proposal).

  A list that is empty, longer than 100, or holds an entry without a valid
  DID or with non-boolean access is refused locally as
  `{:error, :invalid_members}`.
  """
  @spec put_members(String.t(), String.t(), [member()], keyword(), keyword()) ::
          :ok | {:error, term()}
  def put_members(pds, space_ref, members, auth, opts \\ []) do
    with {:ok, entries} <- member_entries(members) do
      body = %{"space" => space_ref, "members" => entries}

      with {:ok, _} <- XRPC.procedure(pds, "#{@nsid}.putMembers", body, auth, opts), do: :ok
    end
  end

  @doc """
  Remove members (`com.atproto.memberspace.removeMembers`) by DID, 1 to 100
  per call, in one commit. DIDs that are not members are ignored by the host.
  An empty, oversized or malformed list is `{:error, :invalid_members}`.
  """
  @spec remove_members(String.t(), String.t(), [String.t()], keyword(), keyword()) ::
          :ok | {:error, term()}
  def remove_members(pds, space_ref, dids, auth, opts \\ []) do
    if batch?(dids) and Enum.all?(dids, &DID.valid?/1) do
      body = %{"space" => space_ref, "dids" => dids}

      with {:ok, _} <- XRPC.procedure(pds, "#{@nsid}.removeMembers", body, auth, opts), do: :ok
    else
      {:error, :invalid_members}
    end
  end

  @doc """
  The `com.atproto.memberspace.member` record a PDS publishes (keyed by the
  member's DID) in the authority's repo when the policy sets
  `publish_members`. Only authoritative in the authority's repo.
  """
  @spec member_record(boolean(), boolean()) :: map()
  def member_record(read, write) when is_boolean(read) and is_boolean(write),
    do: %{"$type" => "#{@nsid}.member", "read" => read, "write" => write}

  @doc """
  List the members (`com.atproto.memberspace.listMembers`), paged with
  `:limit`/`:cursor`. Returns `{:ok, %{"members" => [%{"did", "read",
  "write"}], "cursor" => …}}` — each entry a
  `com.atproto.memberspace.defs#member`.
  """
  @spec list_members(String.t(), String.t(), keyword(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def list_members(pds, space_ref, auth, opts \\ []) do
    params = %{
      "space" => space_ref,
      "limit" => Keyword.get(opts, :limit),
      "cursor" => Keyword.get(opts, :cursor)
    }

    XRPC.query(pds, "#{@nsid}.listMembers", params, auth, opts)
  end

  @doc """
  A `com.atproto.memberspace.defs#member` in its wire shape — the entry
  `putMembers` takes and `listMembers` returns.
  """
  @spec member(String.t(), boolean(), boolean()) :: map()
  def member(did, read, write) when is_binary(did) and is_boolean(read) and is_boolean(write),
    do: %{"did" => did, "read" => read, "write" => write}

  @doc """
  Decode a received `com.atproto.memberspace.putMembers` body for a space
  host: `{:ok, %{space: space_ref, members: [%{did:, read:, write:}]}}`.

  At most 100 entries, each a `defs#member` with a valid DID and both
  booleans. A DID listed more than once takes its *last* entry, keeping the
  position of its first (the reference keys the batch by DID), so the host
  writes each member once per commit. An empty list is lexicon-valid and
  decodes to no members. Anything else is `{:error, :invalid_request}`.
  """
  @spec decode_put_members(map()) ::
          {:ok, %{space: String.t(), members: [access()]}} | {:error, :invalid_request}
  def decode_put_members(%{"space" => space, "members" => members})
      when is_list(members) and length(members) <= @max_batch do
    with true <- XRPC.space_ref?(space),
         {:ok, entries} <- decode_members(members) do
      {:ok, %{space: space, members: last_entry_wins(entries)}}
    else
      _ -> {:error, :invalid_request}
    end
  end

  def decode_put_members(_), do: {:error, :invalid_request}

  @doc """
  Decode a received `com.atproto.memberspace.removeMembers` body for a space
  host: `{:ok, %{space: space_ref, dids: [did]}}`, at most 100 valid DIDs,
  duplicates dropped. Removing a DID that is not a member is the host's to
  ignore (leaving any writer set entry alone). Anything else is
  `{:error, :invalid_request}`.
  """
  @spec decode_remove_members(map()) ::
          {:ok, %{space: String.t(), dids: [String.t()]}} | {:error, :invalid_request}
  def decode_remove_members(%{"space" => space, "dids" => dids})
      when is_list(dids) and length(dids) <= @max_batch do
    if XRPC.space_ref?(space) and Enum.all?(dids, &DID.valid?/1),
      do: {:ok, %{space: space, dids: Enum.uniq(dids)}},
      else: {:error, :invalid_request}
  end

  def decode_remove_members(_), do: {:error, :invalid_request}

  defp decode_members(members) do
    Enum.reduce_while(members, {:ok, []}, fn
      %{"did" => did, "read" => read, "write" => write}, {:ok, acc}
      when is_binary(did) and is_boolean(read) and is_boolean(write) ->
        if DID.valid?(did),
          do: {:cont, {:ok, [%{did: did, read: read, write: write} | acc]}},
          else: {:halt, :error}

      _, _ ->
        {:halt, :error}
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      :error -> :error
    end
  end

  # Order of first appearance, value of last appearance — a JS `Map` built
  # from the list, as the reference does.
  defp last_entry_wins(entries) do
    last = Map.new(entries, &{&1.did, &1})

    entries
    |> Enum.map(& &1.did)
    |> Enum.uniq()
    |> Enum.map(&Map.fetch!(last, &1))
  end

  defp batch?(list), do: is_list(list) and list != [] and length(list) <= @max_batch

  defp member_entries(members) do
    if batch?(members) do
      members
      |> Enum.map(&member_entry/1)
      |> Enum.reduce_while({:ok, []}, fn
        {:ok, entry}, {:ok, acc} -> {:cont, {:ok, [entry | acc]}}
        :error, _ -> {:halt, {:error, :invalid_members}}
      end)
      |> case do
        {:ok, entries} -> {:ok, Enum.reverse(entries)}
        error -> error
      end
    else
      {:error, :invalid_members}
    end
  end

  defp member_entry(did) when is_binary(did), do: member_entry(%{did: did})

  defp member_entry(%{did: did} = member) when is_binary(did) do
    read = Map.get(member, :read, true)
    write = Map.get(member, :write, true)

    if DID.valid?(did) and is_boolean(read) and is_boolean(write),
      do: {:ok, %{"did" => did, "read" => read, "write" => write}},
      else: :error
  end

  defp member_entry(_), do: :error
end
