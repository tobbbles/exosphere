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

  Changes are batched: since atproto `atproto-spaces-lexicon-review`
  (carried by `atproto-spaces-cleanup` 4037310) `putMember`/`removeMember`
  are `putMembers`/`removeMembers`, each taking up to 100 entries applied in
  a single commit. `put_member/5` and `remove_member/5` are gone; pass a
  one-element list.

  OAuth-authenticated as the space authority (`manage=update` for writes,
  `read_self` for `list_members/4`): pass `session:` or `headers:` as for
  `Spaces.Space`. A space credential cannot list members — to make the list
  visible to readers, set the policy's `publish_members`. A caller that is
  not the authority is refused `NotAuthorized` (was `NotSpaceOwner`),
  returned as `{:error, :not_authorized}`; a cursor the host cannot read is
  `{:error, :invalid_cursor}`.
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
