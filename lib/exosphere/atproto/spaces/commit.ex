defmodule Exosphere.ATProto.Spaces.Commit do
  @moduledoc """
  Commits over permissioned repos (proposal 0016, "Space repos"; atproto
  `5791385`).

  A commit (`com.atproto.space.defs#commit`) summarizes one account's repo in
  one space:

  | Field | Type | |
  |---|---|---|
  | `ver` | integer | commit format version, `1` |
  | `repo` | DID | author of the repo |
  | `space` | space ref | `at://authority/space/type/skey` |
  | `rev` | TID | commit revision |
  | `data` | bytes | `sha256` of the repo's LtHash state (32 bytes) |

  It carries **no signature**. A repo host authenticates a commit to each
  syncer with a MAC keyed by a per-request shared secret (`Spaces.Kem`,
  `Spaces.Mac`), sent in the `Atproto-Space-Mac` response header — so a
  syncer gets integrity and a leaked commit proves nothing to a third party.
  `verify/4` checks that MAC and that the commit names the repo and space
  that were asked for; once it passes, `data` is trusted as the author's
  claim, which is what makes comparing a locally-folded set hash against it
  (`matches?/2`) meaningful.

  Until atproto `5791385` (2026-10-27) the commit was a signed
  `defs#signedCommit{ver, hash, ikm, sig, mac, rev}` verified against the
  author's `#atproto` key; that format and its signing are gone.

  Commits are maps with string keys in the wire shape; `data` is a raw
  binary (`to_dag_cbor/1` wraps it as a CBOR byte string for encoding).
  """

  alias Exosphere.ATProto.Spaces.{Lthash, Mac}

  @version 1

  @type t :: %{required(String.t()) => term()}
  @type ctx :: %{required(:space) => String.t(), required(:repo) => String.t()}

  @doc "The current commit format version."
  @spec version() :: pos_integer()
  def version, do: @version

  @doc """
  The commit over a repo's current contents: `lthash` is its set hash, `ctx`
  names the `space`, `repo` and `rev`.
  """
  @spec build(Lthash.t(), %{space: String.t(), repo: String.t(), rev: String.t()}) :: t()
  def build(%Lthash{} = lthash, %{space: space, repo: repo, rev: rev}) do
    %{
      "ver" => @version,
      "repo" => repo,
      "space" => space,
      "rev" => rev,
      "data" => Lthash.digest(lthash)
    }
  end

  @doc """
  The set-hash element a record contributes: `"{collection}/{rkey}/{cid}"`.

  The encoding stays injective because the outer fields are slash-free (a
  collection is an NSID, a CID string is base32).
  """
  @spec element(String.t(), String.t(), String.t()) :: String.t()
  def element(collection, rkey, cid) when is_binary(cid),
    do: collection <> "/" <> rkey <> "/" <> cid

  @doc """
  The commit as a DAG-CBOR-encodable map: `data` must encode as a CBOR
  *byte* string (major type 2), which an Elixir binary alone cannot say, so it
  is wrapped in the `:cbor` library's byte-string tag.
  """
  @spec to_dag_cbor(t()) :: map()
  def to_dag_cbor(%{} = commit) do
    Map.new(commit, fn
      {"data", binary} when is_binary(binary) -> {"data", %CBOR.Tag{tag: :bytes, value: binary}}
      pair -> pair
    end)
  end

  @doc "Fold a record into a set hash (adding for a new record)."
  @spec add_record(Lthash.t(), String.t(), String.t(), String.t()) :: Lthash.t()
  def add_record(%Lthash{} = hash, collection, rkey, cid),
    do: Lthash.add(hash, element(collection, rkey, cid))

  @doc "Remove a record's contribution from a set hash."
  @spec remove_record(Lthash.t(), String.t(), String.t(), String.t()) :: Lthash.t()
  def remove_record(%Lthash{} = hash, collection, rkey, cid),
    do: Lthash.remove(hash, element(collection, rkey, cid))

  @doc """
  Fold an oplog op into a set hash: remove the `prev` CID if present, add the
  new CID unless the op is a delete (`cid` nil). Ops use the lexicon shape —
  string keys `"collection"`, `"rkey"`, `"cid"`, `"prev"` — with CIDs as CID
  strings.
  """
  @spec apply_op(Lthash.t(), map()) :: Lthash.t()
  def apply_op(%Lthash{} = hash, %{} = op) do
    hash
    |> maybe_remove_prev(op)
    |> maybe_add_cid(op)
  end

  @doc """
  Whether a set hash matches a commit's `data`. Verify the commit first — on
  its own this says nothing about authenticity.
  """
  @spec matches?(Lthash.t(), t()) :: boolean()
  def matches?(%Lthash{} = hash, %{"data" => data}) when is_binary(data),
    do: Mac.equal?(Lthash.digest(hash), data)

  def matches?(_, _), do: false

  @doc "The commit MAC under `shared_secret` (what a repo host sends)."
  @spec mac(t(), binary()) :: binary()
  def mac(%{} = commit, shared_secret), do: Mac.commit_mac(shared_secret, commit)

  @doc """
  Verify a commit against the MAC its response carried: the format version,
  the shape, that `repo` and `space` are the ones requested (`ctx`), and the
  MAC under the request's shared secret.

  Errors: `:invalid_commit` (shape/version), `:repo_mismatch`,
  `:space_mismatch`, `:invalid_mac`. On `:invalid_mac` the proposal advises
  refreshing the author's DID document (the KEM key may have rotated) before
  retrying with a new key share.
  """
  @spec verify(t(), ctx(), binary(), binary()) :: :ok | {:error, term()}
  def verify(%{} = commit, %{space: space, repo: repo}, shared_secret, mac) do
    cond do
      not well_formed?(commit) -> {:error, :invalid_commit}
      commit["repo"] != repo -> {:error, :repo_mismatch}
      commit["space"] != space -> {:error, :space_mismatch}
      not Mac.equal?(Mac.commit_mac(shared_secret, commit), mac) -> {:error, :invalid_mac}
      true -> :ok
    end
  end

  def verify(_, _, _, _), do: {:error, :invalid_commit}

  @doc "Whether a map has the commit's shape and the supported version."
  @spec well_formed?(term()) :: boolean()
  def well_formed?(%{
        "ver" => @version,
        "repo" => repo,
        "space" => space,
        "rev" => rev,
        "data" => data
      })
      when is_binary(repo) and is_binary(space) and is_binary(rev) and is_binary(data) and
             byte_size(data) == 32,
      do: true

  def well_formed?(_), do: false

  defp maybe_remove_prev(hash, %{"prev" => prev, "collection" => c, "rkey" => r})
       when is_binary(prev),
       do: Lthash.remove(hash, element(c, r, prev))

  defp maybe_remove_prev(hash, _op), do: hash

  defp maybe_add_cid(hash, %{"cid" => cid, "collection" => c, "rkey" => r})
       when is_binary(cid),
       do: Lthash.add(hash, element(c, r, cid))

  defp maybe_add_cid(hash, _op), do: hash
end
