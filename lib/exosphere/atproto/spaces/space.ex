defmodule Exosphere.ATProto.Spaces.Space do
  @moduledoc """
  Space administration on the authority's PDS (proposal 0016, "Space policy";
  atproto `7992095`): the policy-agnostic `com.atproto.space.*` methods that
  create, describe, reconfigure, and delete a space.

  A space is created with a single `policy` object (`Spaces.Policy`) and
  `update_space/5` replaces it wholesale — a policy with a different `$type`
  migrates the space, discarding state the previous policy held (such as a
  memberspace member list). A host that does not implement the policy answers
  `UnsupportedPolicy`.

      {:ok, %{"uri" => space}} =
        Space.create_space(pds, "com.example.group", Policy.member(publish_policy: true),
          session: session, skey: "general")

  Policy-specific methods live with their policy: the member list in
  `Spaces.Memberspace`, the managing-app check in `Spaces.Managedspace`.

  These methods are OAuth-authenticated as the space owner: pass
  `session: %OAuth.Session{}` (DPoP-bound, with nonce retries) or
  `headers: [{"authorization", ...}]`. The covering `space:` scope grant is
  `manage=create`/`update`/`delete`, or `read_self` for `get_space/4`.

  XRPC errors surface as `{:error, {:http_error, status, name}}` — e.g.
  `"SpaceAlreadyExists"`, `"UnsupportedPolicy"`, `"NotSpaceOwner"`,
  `"SpaceNotFound"`. Request options (`:timeout`, `:follow_redirects`) and
  `:http` travel in the same keyword list as the auth.

  This replaces `Spaces.SimpleSpace` and the `com.atproto.simplespace`
  namespace, which upstream removed.
  """

  alias Exosphere.ATProto.Spaces.Policy
  alias Exosphere.ATProto.Spaces.XRPC

  @nsid "com.atproto.space"

  @doc """
  Create a space (`com.atproto.space.createSpace`) governed by `policy`. The
  space is anchored on the authenticated user's DID, who becomes its owner.

  `space_type` is the space type's NSID. Option `:skey` sets the space key
  (a TID is generated when omitted). Returns `{:ok, %{"uri" => space_ref}}`.
  """
  @spec create_space(String.t(), String.t(), Policy.t(), keyword(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def create_space(pds, space_type, %{"$type" => _} = policy, auth, opts \\ []) do
    body = %{"spaceType" => space_type, "skey" => Keyword.get(opts, :skey), "policy" => policy}
    XRPC.procedure(pds, "#{@nsid}.createSpace", body, auth, opts)
  end

  @doc """
  Replace a space's policy (`com.atproto.space.updateSpace`). The new policy
  replaces the current one wholesale; a different `$type` migrates the space.
  """
  @spec update_space(String.t(), String.t(), Policy.t(), keyword(), keyword()) ::
          :ok | {:error, term()}
  def update_space(pds, space_ref, %{"$type" => _} = policy, auth, opts \\ []) do
    body = %{"space" => space_ref, "policy" => policy}

    with {:ok, _} <- XRPC.procedure(pds, "#{@nsid}.updateSpace", body, auth, opts), do: :ok
  end

  @doc """
  Delete a space (`com.atproto.space.deleteSpace`). The owner's own repo in
  the space is deleted; other members' repos are left in place. Afterwards
  reads and writes fail with `SpaceNotFound` and `getSpaceCredential` answers
  `SpaceDeleted`. Idempotent.
  """
  @spec delete_space(String.t(), String.t(), keyword(), keyword()) :: :ok | {:error, term()}
  def delete_space(pds, space_ref, auth, opts \\ []) do
    with {:ok, _} <-
           XRPC.procedure(pds, "#{@nsid}.deleteSpace", %{"space" => space_ref}, auth, opts),
         do: :ok
  end

  @doc """
  Describe a space (`com.atproto.space.getSpace`): `{:ok, %{"uri" => …,
  "policy" => …}}`. Requires the owner's `read_self` grant — a space
  credential is not accepted. Decode the policy with `Spaces.Policy.decode/1`.
  """
  @spec get_space(String.t(), String.t(), keyword(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def get_space(host, space_ref, auth, opts \\ []) do
    XRPC.query(host, "#{@nsid}.getSpace", %{"space" => space_ref}, auth, opts)
  end

  @doc """
  The spaces the authenticated user holds a repo in or is the authority of
  (`com.atproto.space.listSpaces`) — not "spaces I'm a member of": a member's
  PDS only tracks spaces its user has written to.

  Options: `:space_type` (NSID filter), `:did` (authority filter), `:limit`,
  `:cursor`. Returns `{:ok, %{"spaces" => [%{"uri" => …}], "cursor" => …}}`.
  """
  @spec list_spaces(String.t(), keyword(), keyword()) :: {:ok, map()} | {:error, term()}
  def list_spaces(pds, auth, opts \\ []) do
    params = %{
      "spaceType" => Keyword.get(opts, :space_type),
      "did" => Keyword.get(opts, :did),
      "limit" => Keyword.get(opts, :limit),
      "cursor" => Keyword.get(opts, :cursor)
    }

    XRPC.query(pds, "#{@nsid}.listSpaces", params, auth, opts)
  end
end
