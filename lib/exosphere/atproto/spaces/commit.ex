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
  syncer with an RFC 9421 `hmac-sha256` signature keyed by a per-request HPKE
  secret (`Spaces.Kem`, `Spaces.Mac`): an `Atproto-Space-Commit` header
  describing the commit, signed under the label the syncer asked for in
  `Accept-Signature`. A syncer gets integrity, and a leaked commit proves
  nothing to a third party. The host builds those headers with
  `mac_headers/2`; `verify/4` checks the commit's shape, that it names the
  repo and space that were asked for, and the MAC over a header matching it.
  Once it passes, `data` is trusted as the author's claim, which is what
  makes comparing a locally-folded set hash against it (`matches?/2`)
  meaningful.

  Until the November 12 alpha the MAC was a bare HMAC over a length-prefixed
  context, sent in `Atproto-Space-Mac`; that format is gone.

  Until atproto `5791385` (2026-10-27) the commit was a signed
  `defs#signedCommit{ver, hash, ikm, sig, mac, rev}` verified against the
  author's `#atproto` key; that format and its signing are gone.

  Commits are maps with string keys in the wire shape; `data` is a raw
  binary (`to_dag_cbor/1` wraps it as a CBOR byte string for encoding).
  """

  alias Exosphere.ATProto.Identity.DID
  alias Exosphere.ATProto.Spaces.{HttpSignature, Kem, Lthash, Mac, XRPC}
  alias Exosphere.ATProto.TID

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

  @doc """
  The response headers a repo host adds for `commit` (`getLatestCommit`,
  `listRepoOps`, `getRepo`): `atproto-space-commit`, `signature-input` and
  `signature`, keyed by the request's decapsulated secret (`mac_params`, from
  `Spaces.Mac.parse_request/2` and `Spaces.Mac.decapsulate/2`). See
  `Spaces.Mac.commit_headers/2`.
  """
  @spec mac_headers(t(), Mac.mac_params()) :: [{String.t(), String.t()}]
  def mac_headers(%{} = commit, mac_params), do: Mac.commit_headers(commit, mac_params)

  @doc """
  Verify a commit against the MAC its response carried: the format version
  and shape, that `repo` and `space` are the ones requested (`ctx`), and the
  commit MAC in the response `headers`, under the `encapsulation` the request
  was made with (`Spaces.Kem.encapsulate/2`), over an `Atproto-Space-Commit`
  header that matches the commit field for field.

  Errors: `:invalid_commit` (shape/version), `:repo_mismatch`,
  `:space_mismatch`, `{:invalid_space_mac, reason}` (`Spaces.Mac`). On a MAC
  failure the proposal advises refreshing the author's DID document (the KEM
  key may have rotated) before retrying with a new key share.
  """
  @spec verify(t(), ctx(), Kem.encapsulation(), HttpSignature.headers()) ::
          :ok | {:error, term()}
  def verify(%{} = commit, %{space: space, repo: repo}, encapsulation, headers) do
    cond do
      not well_formed?(commit) -> {:error, :invalid_commit}
      commit["repo"] != repo -> {:error, :repo_mismatch}
      commit["space"] != space -> {:error, :space_mismatch}
      true -> Mac.verify_commit(commit, encapsulation, headers)
    end
  end

  def verify(_, _, _, _), do: {:error, :invalid_commit}

  @doc """
  Whether a map has the commit's shape (`com.atproto.space.defs#commit`) and
  the supported version: `repo` a DID, `space` a space-ref, `rev` a TID, and
  a 32-byte `data` digest. The rev is checked as a TID because syncers hand
  it back as the position to resume from (`listRepoOps` `since`, format
  `tid`), and the reference refuses a commit whose rev is not one.
  """
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
      do: DID.valid?(repo) and XRPC.space_ref?(space) and TID.valid?(rev)

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
