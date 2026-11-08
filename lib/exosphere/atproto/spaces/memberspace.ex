defmodule Exosphere.ATProto.Spaces.Memberspace do
  @moduledoc """
  The member list of a space governed by `com.atproto.memberspace.policy`
  (proposal 0016, "`memberspace`"; atproto `7992095`), managed on the
  authority's PDS.

  Each entry carries required `read` and `write` booleans; `put_member/5`
  replaces both together. The list is not part of the policy object: it
  persists across configuration changes and is discarded when the space
  migrates to a different policy. Calling these on a space under another
  policy answers `PolicyMismatch`.

  OAuth-authenticated as the space owner (`manage=update` for writes,
  `read_self` for `list_members/4`): pass `session:` or `headers:` as for
  `Spaces.Space`. A space credential cannot list members — to make the list
  visible to readers, set the policy's `publish_members`.

  These replace `Spaces.SimpleSpace.put_member/5`, `remove_member/5`, and
  `list_members/4` (upstream moved them from `com.atproto.simplespace`).
  """

  alias Exosphere.ATProto.Spaces.XRPC

  @nsid "com.atproto.memberspace"

  @doc """
  Add a member (`com.atproto.memberspace.putMember`), or replace the access
  of one already on the list. `:read` and `:write` both default to `true`;
  `false`/`false` parks a member on the list without access. Revoking write
  access should also drop the member from the writer set (the authority's
  job, per the proposal).
  """
  @spec put_member(String.t(), String.t(), String.t(), keyword(), keyword()) ::
          :ok | {:error, term()}
  def put_member(pds, space_ref, did, auth, opts \\ []) do
    body = %{
      "space" => space_ref,
      "did" => did,
      "read" => Keyword.get(opts, :read, true),
      "write" => Keyword.get(opts, :write, true)
    }

    with {:ok, _} <- XRPC.procedure(pds, "#{@nsid}.putMember", body, auth, opts), do: :ok
  end

  @doc "Remove a member (`com.atproto.memberspace.removeMember`)."
  @spec remove_member(String.t(), String.t(), String.t(), keyword(), keyword()) ::
          :ok | {:error, term()}
  def remove_member(pds, space_ref, did, auth, opts \\ []) do
    body = %{"space" => space_ref, "did" => did}

    with {:ok, _} <- XRPC.procedure(pds, "#{@nsid}.removeMember", body, auth, opts), do: :ok
  end

  @doc """
  List the members (`com.atproto.memberspace.listMembers`), paged with
  `:limit`/`:cursor`. Returns `{:ok, %{"members" => [%{"did", "read",
  "write"}], "cursor" => …}}`.
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
end
