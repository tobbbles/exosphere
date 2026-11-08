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

      {:ok, %{"space" => space}} =
        Space.create_space(pds, "com.example.group", Policy.member(publish_policy: true),
          session: session, skey: "general")

  Policy-specific methods live with their policy: the member list in
  `Spaces.Memberspace`, the managing-app check in `Spaces.Managedspace`.

  These methods are OAuth-authenticated as the space authority: pass
  `session: %OAuth.Session{}` (DPoP-bound, with nonce retries) or
  `headers: [{"authorization", ...}]`. The covering `space:` scope grant is
  `manage=create`/`update`/`delete`, or `read_self` for `get_space/4`.

  XRPC errors surface as `{:error, {:http_error, status, name}}` — e.g.
  `"SpaceAlreadyExists"`, `"UnsupportedPolicy"`, `"SpaceNotFound"` — except
  the names atproto `atproto-spaces-lexicon-review` / `atproto-spaces-cleanup`
  (4037310) introduced, which are typed: a caller that is not the space
  authority gets `{:error, :not_authorized}` (`NotAuthorized`, which was
  `NotSpaceOwner`), a bad listing cursor `{:error, :invalid_cursor}`, and a
  malformed import `{:error, :invalid_space_meta}`. Request options
  (`:timeout`, `:follow_redirects`) and `:http` travel in the same keyword
  list as the auth.

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
  (a TID is generated when omitted). Returns `{:ok, %{"space" => space_ref}}`
  (the output field was `uri` until atproto `atproto-spaces-lexicon-review`).
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
  Describe a space (`com.atproto.space.getSpace`): `{:ok, %{"space" => …,
  "policy" => …}}` (the space ref was `uri` until atproto
  `atproto-spaces-lexicon-review`). Requires the authority's `read_self`
  grant — a space credential is not accepted. Decode the policy with
  `Spaces.Policy.decode/1`.
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

  Options: `:space_type` (NSID filter), `:space_did` (authority filter; the
  parameter was `did`, and this option `:did`, until atproto
  `atproto-spaces-cleanup` 4037310), `:limit`, `:cursor`.

  Returns `{:ok, %{"spaces" => [view], "cursor" => …}}`, each view a
  `listSpaces#spaceView` in its wire shape: `"space"` (the space ref; it was
  `"uri"`), and — when the account holds a repo in the space — that repo's
  `"repoRev"`, `"spaceRev"` and commit `"data"` (lexicon `bytes`, i.e.
  `%{"$bytes" => base64}`), new at 4037310.
  """
  @spec list_spaces(String.t(), keyword(), keyword()) :: {:ok, map()} | {:error, term()}
  def list_spaces(pds, auth, opts \\ []) do
    params = %{
      "spaceType" => Keyword.get(opts, :space_type),
      "spaceDid" => Keyword.get(opts, :space_did),
      "limit" => Keyword.get(opts, :limit),
      "cursor" => Keyword.get(opts, :cursor)
    }

    XRPC.query(pds, "#{@nsid}.listSpaces", params, auth, opts)
  end

  @doc """
  Remove an account's repo from the space's writer set
  (`com.atproto.space.removeWriter`, atproto `937ddb9`), so `listWriters` no
  longer lists it. The repo DID is sent as `repo` (it was `did` until atproto
  `atproto-spaces-lexicon-review`). Idempotent; the account is tracked again
  if it later writes while still authorized. Requires auth as an account that
  may manage the space (`manage=update`).
  """
  @spec remove_writer(String.t(), String.t(), String.t(), keyword(), keyword()) ::
          :ok | {:error, term()}
  def remove_writer(host, space_ref, repo, auth, opts \\ []) do
    body = %{"space" => space_ref, "repo" => repo}

    with {:ok, _} <- XRPC.procedure(host, "#{@nsid}.removeWriter", body, auth, opts), do: :ok
  end

  @doc """
  Download a space's host-side state as a space meta archive
  (`com.atproto.space.exportSpaceMeta`, atproto `35c0cf1`), for account
  migration: `{:ok, star_bytes}` (served as `application/vnd.dasl.star` since
  4037310), decodable with `Spaces.SpaceMeta.decode/1`. Requires the
  authority's `read_self` grant.
  """
  @spec export_space_meta(String.t(), String.t(), keyword(), keyword()) ::
          {:ok, binary()} | {:error, term()}
  def export_space_meta(host, space_ref, auth, opts \\ []) do
    XRPC.query_bytes(host, "#{@nsid}.exportSpaceMeta", %{"space" => space_ref}, auth, opts)
  end

  @doc """
  Import a space from a space meta archive (`com.atproto.space.importSpaceMeta`)
  on the account's new host, replacing whatever it holds for that space. The
  space must be anchored on the authenticated account; this must come before
  importing the account's own repo in the space (`Spaces.Writes.import_repo/4`).
  Requires `manage=create` and `manage=update`. A policy the host does not
  implement is refused with `UnsupportedPolicy`, and a malformed archive with
  `InvalidSpaceMeta` (`{:error, :invalid_space_meta}`). The archive is sent
  as `application/vnd.dasl.star`.
  """
  @spec import_space_meta(String.t(), binary(), keyword(), keyword()) :: :ok | {:error, term()}
  def import_space_meta(pds, star, auth, opts \\ []) when is_binary(star) do
    with {:ok, _} <- XRPC.procedure_bytes(pds, "#{@nsid}.importSpaceMeta", star, auth, opts),
         do: :ok
  end

  @doc """
  Whether a PDS advertises the Spaces alpha: `spacesAlpha: true` in its
  unauthenticated `com.atproto.server.describeServer` response (atproto
  `fb2cf00`). The flag is an implementation signal, not a lexicon field, and
  will go away when spaces leave alpha; treat `{:ok, false}` as "unknown or
  no", not as a refusal.
  """
  @spec spaces_alpha?(String.t(), keyword()) :: {:ok, boolean()} | {:error, term()}
  def spaces_alpha?(pds, opts \\ []) do
    http = Keyword.get(opts, :http, Exosphere.ATProto.HTTP)
    url = "#{String.trim_trailing(pds, "/")}/xrpc/com.atproto.server.describeServer"

    case XRPC.classify(http.get(url, Exosphere.ATProto.HTTP.take_request_opts(opts))) do
      {:ok, body} -> {:ok, Map.get(body, "spacesAlpha") == true}
      error -> error
    end
  end
end
