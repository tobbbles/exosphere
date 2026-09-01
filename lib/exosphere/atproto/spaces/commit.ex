defmodule Exosphere.ATProto.Spaces.Commit do
  @moduledoc """
  Signed commits over permissioned repos (atproto proposal 0016).

  A commit's signature covers only the commit *context* — never the repo
  digest — so a leaked commit proves nothing about what the author wrote. The
  digest is bound to the context instead by a symmetric MAC keyed with fresh
  per-commit input keying material: readers get integrity, third parties get
  deniability.

  The context (`encode_ctx/4`) is domain-separated and length-prefixed:

      ctx = "atproto-space-v1"
         || uint16be(len(space))  || space
         || uint16be(len(author)) || author
         || uint16be(len(rev))    || rev
         || uint16be(len(ikm))    || ikm

  and the MAC is `HMAC-SHA256(HKDF-Expand(ikm, info = ctx, 32), hash)` —
  expand-only, since the ikm is uniform.

  The commit itself is the DAG-CBOR object `com.atproto.space.defs#signedCommit`
  (`ver`, `hash`, `ikm`, `sig`, `mac`, `rev`); the context fields (space,
  author) arrive with the surrounding request and must be supplied to
  `verify/4` — a commit on its own does not say which space it belongs to.
  """

  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.Spaces.Lthash

  @version 1
  @domain_tag "atproto-space-v1"

  @type ctx :: %{
          required(:space) => String.t(),
          required(:author) => String.t(),
          required(:rev) => String.t()
        }

  @type t :: %{
          required(String.t()) => term(),
          optional(String.t()) => term()
        }

  @doc """
  Encode the commit context string that both the signature and the MAC cover.

  Length prefixes are big-endian per the TLS variable-length vector convention
  — deliberately the opposite byte order from the set hash's little-endian
  lanes.
  """
  @spec encode_ctx(ctx(), binary()) :: binary()
  def encode_ctx(%{space: space, author: author, rev: rev}, ikm)
      when is_binary(space) and is_binary(author) and is_binary(rev) and is_binary(ikm) do
    fields = [space, author, rev, ikm]

    if Enum.any?(fields, &(byte_size(&1) > 0xFFFF)) do
      raise ArgumentError, "commit ctx field exceeds uint16 length prefix"
    end

    IO.iodata_to_binary([
      @domain_tag
      | Enum.flat_map(fields, fn field ->
          [<<byte_size(field)::big-integer-size(16)>>, field]
        end)
    ])
  end

  @doc """
  The set-hash element a record contributes:
  `"{collection}/{rkey}/{cid}"`.

  The encoding stays injective because the outer fields are slash-free (a
  collection is an NSID, a CID string is base32), not because of length
  prefixes.
  """
  @spec element(String.t(), String.t(), String.t()) :: String.t()
  def element(collection, rkey, cid) when is_binary(cid),
    do: collection <> "/" <> rkey <> "/" <> cid

  @doc """
  Fold a record into a set hash (adding for a new record).
  """
  @spec add_record(Lthash.t(), String.t(), String.t(), String.t()) :: Lthash.t()
  def add_record(%Lthash{} = hash, collection, rkey, cid),
    do: Lthash.add(hash, element(collection, rkey, cid))

  @doc """
  Remove a record's contribution from a set hash (deletes and `prev` CIDs on
  updates).
  """
  @spec remove_record(Lthash.t(), String.t(), String.t(), String.t()) :: Lthash.t()
  def remove_record(%Lthash{} = hash, collection, rkey, cid),
    do: Lthash.remove(hash, element(collection, rkey, cid))

  @doc """
  Fold an oplog op into a set hash: remove the `prev` CID if present, add the
  new CID unless the op is a delete (`cid` nil). Ops use the lexicon shape —
  string keys `"collection"`, `"rkey"`, `"cid"`, `"prev"` — with CIDs as
  CID strings; `nil` for a create's `prev` and a delete's `cid`.
  """
  @spec apply_op(Lthash.t(), map()) :: Lthash.t()
  def apply_op(%Lthash{} = hash, %{} = op) do
    hash
    |> maybe_remove_prev(op)
    |> maybe_add_cid(op)
  end

  @doc """
  Sign the current contents of a permissioned repo as a commit.

  `hash` is the `Lthash` of the repo's records; a fresh 32-byte `ikm` is
  generated per call, so every reader receives a distinct commit and no two
  commits share MAC or signature.

  Returns the `signedCommit` object as a DAG-CBOR-ready map.
  """
  @spec sign(Lthash.t(), ctx(), binary(), Crypto.curve()) ::
          {:ok, t()} | {:error, term()}
  def sign(%Lthash{} = hash, %{} = ctx, private_key, curve) do
    digest = Lthash.digest(hash)
    ikm = :crypto.strong_rand_bytes(32)
    ctx_bytes = encode_ctx(ctx, ikm)

    with {:ok, sig} <- Crypto.sign(ctx_bytes, private_key, curve) do
      {:ok,
       %{
         "ver" => @version,
         "hash" => digest,
         "ikm" => ikm,
         "mac" => compute_mac(ikm, ctx_bytes, digest),
         "sig" => sig,
         "rev" => ctx.rev
       }}
    end
  end

  @doc """
  Verify a commit's MAC (integrity) and signature (authenticity).

  Once this returns `:ok`, the commit's `hash` is trusted as the author's
  claim about their repo — which is what makes comparing a locally-folded set
  hash against it (`Lthash.digest/1` equality) meaningful.

  `public_key` is the author's account signing key (`#atproto`), with its
  curve.
  """
  @spec verify(t(), ctx(), binary(), Crypto.curve()) :: :ok | {:error, term()}
  def verify(%{} = commit, %{} = ctx, public_key, curve) do
    with :ok <- check_shape(commit),
         :ok <- check_rev(commit, ctx),
         :ok <- check_mac(commit, ctx) do
      Crypto.verify(encode_ctx(ctx, commit["ikm"]), commit["sig"], public_key, curve)
    end
  end

  def verify(_, _, _, _), do: {:error, :invalid_commit}

  defp check_shape(commit) do
    bytes32 = ["hash", "mac", "ikm"]

    if commit["ver"] == @version and
         Enum.all?(bytes32, &(is_binary(commit[&1]) and byte_size(commit[&1]) == 32)) and
         is_binary(commit["sig"]) and byte_size(commit["sig"]) > 0 and is_binary(commit["rev"]) do
      :ok
    else
      {:error, :invalid_commit}
    end
  end

  defp maybe_remove_prev(hash, %{"prev" => prev, "collection" => c, "rkey" => r})
       when is_binary(prev),
       do: Lthash.remove(hash, element(c, r, prev))

  defp maybe_remove_prev(hash, _op), do: hash

  defp maybe_add_cid(hash, %{"cid" => cid, "collection" => c, "rkey" => r})
       when is_binary(cid),
       do: Lthash.add(hash, element(c, r, cid))

  defp maybe_add_cid(hash, _op), do: hash

  defp check_rev(commit, ctx) do
    if commit["rev"] == ctx.rev, do: :ok, else: {:error, :rev_mismatch}
  end

  defp check_mac(commit, ctx) do
    expected = compute_mac(commit["ikm"], encode_ctx(ctx, commit["ikm"]), commit["hash"])

    if :crypto.hash_equals(expected, commit["mac"]) do
      :ok
    else
      {:error, :invalid_mac}
    end
  end

  defp compute_mac(ikm, ctx_bytes, digest) do
    :crypto.mac(:hmac, :sha256, hkdf_expand(ikm, ctx_bytes), digest)
  end

  # HKDF-Expand (RFC 5869 §2.3), one block: T(1) = HMAC(PRK, info || 0x01).
  # Extract is skipped — the ikm is already a uniform 32-byte key.
  defp hkdf_expand(prk, info) do
    :crypto.mac(:hmac, :sha256, prk, info <> <<1>>)
  end
end
