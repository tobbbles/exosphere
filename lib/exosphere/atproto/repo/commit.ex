defmodule Exosphere.ATProto.Repo.Commit do
  @moduledoc """
  Repository commit signature verification.

  Every repository commit is a DAG-CBOR object carrying a `sig` field: the raw
  ECDSA signature, in low-S form, over the SHA-256 of the *unsigned* commit
  (the same object with the `sig` field removed) encoded as canonical DAG-CBOR.

  This module builds and signs commits, and verifies them against an account's
  signing key, tying together `Exosphere.ATProto.CBOR`,
  `Exosphere.ATProto.Crypto`, and `Exosphere.ATProto.Identity`.

  ## Examples

      # Serving: build a commit over a new MST root and sign it
      commit =
        Exosphere.ATProto.Repo.Commit.build(did, mst_root, rev)
        |> Exosphere.ATProto.Repo.Commit.sign!(private_key, :secp256k1)

      # With an explicit public key + curve
      :ok = Exosphere.ATProto.Repo.Commit.verify(commit, public_key, :secp256k1)

      # Or resolve the signing key straight from a DID Document
      :ok = Exosphere.ATProto.Repo.Commit.verify_with_document(commit, did_document)

  ## `sig` and the bytes asymmetry

  `sign/3` puts the signature in as a tagged CBOR byte string
  (`%CBOR.Tag{tag: :bytes}`), which is what `Exosphere.ATProto.CBOR.encode/1`
  needs to emit major type 2 rather than a text string. Decoding goes the other
  way: `Exosphere.ATProto.CBOR.transform_links/1` unwraps byte strings to plain
  binaries, which are friendlier to work with but no longer distinguishable
  from text on the way back out.

  The practical consequence for a server: **keep commit blocks as bytes**. A
  decoded commit that is re-encoded produces a different CID, because its `sig`
  comes back as a text string. `Exosphere.ATProto.CAR.decode_raw/1`,
  `Exosphere.ATProto.CAR.encode/3` and the `Exosphere.ATProto.MST` block
  sources all deal in encoded bytes and pass them through untouched, so a
  serving path that never round-trips through a decoded map never hits this.
  """

  # Aliased under a distinct name so `%CBOR.Tag{}` still refers to the `:cbor`
  # library struct.
  alias Exosphere.ATProto.CBOR, as: DagCBOR
  alias Exosphere.ATProto.{CID, Crypto, MST}
  alias Exosphere.ATProto.Identity.Document

  @type commit :: %{optional(String.t()) => term()}

  # The current repository commit format. Version 2 is long gone; a producer
  # emits 3 and a consumer should reject anything else.
  @commit_version 3

  @doc """
  The commit format version this module builds (`3`).
  """
  @spec version() :: pos_integer()
  def version, do: @commit_version

  @doc """
  Build an unsigned commit object.

  `data` is the MST root the commit attests to and `rev` its TID revision,
  which must increase monotonically for the repository. `prev` is a link to the
  preceding commit; the current commit format (version 3) leaves it `null`,
  which is the default.

  The result still needs `sign/3` before it means anything.

  ## Examples

      iex> root = Exosphere.ATProto.CID.create!(%{"l" => nil, "e" => []})
      iex> commit = Exosphere.ATProto.Repo.Commit.build("did:plc:abc", root, "3lbqmqtqhpk2a")
      iex> {commit["version"], commit["prev"]}
      {3, nil}
  """
  @spec build(String.t(), CID.t(), String.t(), keyword()) :: commit()
  def build(did, %CID{} = data, rev, opts \\ []) when is_binary(did) and is_binary(rev) do
    %{
      "did" => did,
      "version" => @commit_version,
      "data" => data,
      "rev" => rev,
      "prev" => Keyword.get(opts, :prev)
    }
  end

  @doc """
  Sign a commit, returning it with its `sig` field.

  The signature covers the SHA-256 of the *unsigned* commit — the same object
  with `sig` removed — encoded as canonical DAG-CBOR, which is exactly what
  `verify/3` recomputes. Any `sig` already present is dropped first, so
  re-signing an existing commit does the right thing.

  The signature goes in as a tagged CBOR byte string; see the note on the
  bytes asymmetry in this module's documentation.
  """
  @spec sign(commit(), binary(), Crypto.curve()) :: {:ok, commit()} | {:error, term()}
  def sign(commit, private_key, curve) when is_map(commit) do
    unsigned = unsigned(commit)

    with {:ok, bytes} <- DagCBOR.encode(unsigned),
         {:ok, sig} <- Crypto.sign(bytes, private_key, curve) do
      {:ok, Map.put(unsigned, "sig", %CBOR.Tag{tag: :bytes, value: sig})}
    end
  end

  @doc """
  Sign a commit, raising on error.
  """
  @spec sign!(commit(), binary(), Crypto.curve()) :: commit()
  def sign!(commit, private_key, curve) do
    case sign(commit, private_key, curve) do
      {:ok, signed} -> signed
      {:error, reason} -> raise ArgumentError, "commit signing failed: #{inspect(reason)}"
    end
  end

  @doc """
  Verify a decoded commit object against a public key.

  The commit is the map produced by decoding the commit block (e.g. via
  `Exosphere.ATProto.CBOR.decode/1` or extracted from a CAR file), with the
  `data` field as an `Exosphere.ATProto.CID` and `sig` as raw bytes.

  Returns `:ok`, or `{:error, reason}` if the signature is missing, malformed,
  or invalid.
  """
  @spec verify(commit(), binary(), Crypto.curve()) ::
          :ok | {:error, :missing_sig | :invalid_signature | term()}
  def verify(commit, public_key, curve) when is_map(commit) do
    with {:ok, sig} <- extract_sig(commit),
         {:ok, bytes} <- DagCBOR.encode(unsigned(commit)) do
      Crypto.verify(bytes, sig, public_key, curve)
    end
  end

  @doc """
  Verify that a commit's `data` field (the MST root) matches a set of records.

  `records` is a `path => CID` map (or enumerable of `{path, %CID{}}`) of every
  record in the repository. The records are assembled into an MST and the
  resulting root CID is compared to the commit's `data` link, confirming the
  commit actually attests to exactly those records.

  Combine with `verify/3` to fully authenticate a repository: `verify/3` proves
  the commit is signed by the account, and `verify_data/2` proves the records
  match the signed root.

  Returns `:ok`, `{:error, :data_mismatch}`, `{:error, :missing_data}`, or any
  error from MST construction.
  """
  @spec verify_data(commit(), Enumerable.t()) ::
          :ok | {:error, :data_mismatch | :missing_data | term()}
  def verify_data(commit, records) do
    with {:ok, root} <- MST.root_cid(records) do
      case Map.get(commit, "data") do
        ^root -> :ok
        %CID{} -> {:error, :data_mismatch}
        _ -> {:error, :missing_data}
      end
    end
  end

  @doc """
  Verify a commit against a block store containing its MST, returning the
  repository's record set.

  `blocks` maps CIDs to encoded DAG-CBOR bytes or decoded nodes (e.g. the
  `blocks` from `CAR.decode_full/1`). The tree is walked from the commit's
  `data` root, and the resulting records are checked against the signed root
  via `verify_data/2`, proving the blocks form exactly the tree the commit
  attests to.

  This is the structural half of repository verification. To also authenticate
  the signer, follow up with `verify/3` or `verify_with_document/2` (or use
  `Exosphere.ATProto.Repo.verify_checkout/3`, which does both).

  Returns `{:ok, records}` (`path => CID`), or errors from `MST.read/2` /
  `verify_data/2` (e.g. `{:error, {:missing_block, cid}}` when the block store
  is incomplete).
  """
  @spec verify_checkout(commit(), %{CID.t() => binary() | map()}) ::
          {:ok, %{MST.key() => CID.t()}} | {:error, term()}
  def verify_checkout(commit, blocks) when is_map(commit) and is_map(blocks) do
    case Map.get(commit, "data") do
      %CID{} = root ->
        with {:ok, records} <- MST.read(root, blocks),
             :ok <- verify_data(commit, records) do
          {:ok, records}
        end

      _ ->
        {:error, :missing_data}
    end
  end

  @doc """
  Verify a commit using the signing key advertised in a DID Document.
  """
  @spec verify_with_document(commit(), Document.t()) ::
          :ok | {:error, :missing_sig | :invalid_signature | :not_found | term()}
  def verify_with_document(commit, %Document{} = doc) do
    with {:ok, public_key, curve} <- Document.get_signing_key(doc) do
      verify(commit, public_key, curve)
    end
  end

  # The `sig` field, normalized to raw bytes. CBOR byte strings decode to raw
  # binaries via Exosphere.ATProto.CBOR.transform_links/1, but tolerate a
  # wrapping :bytes tag too.
  defp extract_sig(commit) do
    case Map.get(commit, "sig") do
      sig when is_binary(sig) -> {:ok, sig}
      %CBOR.Tag{tag: :bytes, value: sig} when is_binary(sig) -> {:ok, sig}
      _ -> {:error, :missing_sig}
    end
  end

  defp unsigned(commit), do: Map.delete(commit, "sig")
end
