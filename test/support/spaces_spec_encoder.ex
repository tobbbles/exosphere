defmodule Exosphere.ATProto.Spaces.SpecEncoder do
  @moduledoc """
  Test-only second encoder for the spaces wire format — the ADR 0025 G6
  carve-out ("a test-only second encoder, written from the spec text by a
  different author, living only in the test suite").

  ## Provenance rule

  Every construction below was written from the **proposal 0016 README**
  ("Commit digest", "Commit signature", "Repo serialization" sections), NOT
  from `Exosphere.ATProto.Spaces.{Lthash,Commit,Repo}` and NOT from the
  reference TypeScript. Where the proposal defers to an external spec, that
  spec's text is the source: RFC 5869 §2.3 for HKDF-Expand, RFC 8446 §3.4 for
  the length-prefixed vector encoding, the DAG-CBOR/DRISL data model for block
  encoding, and the CAR v1 framing for the file layout.

  The single shared primitive is BLAKE3-XOF (through the NIF): it is pinned
  independently three ways already — the official BLAKE3 vectors, the
  pure-Elixir `Blake3.Reference` differential, and the reference corpus — so
  reuse here costs no independence while keeping the property tests fast.

  **This module is test-support only. It must never be imported from `lib/`.**
  """

  alias Exosphere.ATProto.Spaces.Blake3

  @state_bytes 2048
  @domain_tag "atproto-space-v1"

  ## The set hash (LtHash) — proposal "Commit digest"
  ##
  ## "The state is a fixed 2048-byte buffer, interpreted as 1024 little-endian
  ## unsigned 16-bit lanes." To add an element: "Expand the element to 2048
  ## bytes with BLAKE3 in XOF mode… Add each lane into the corresponding state
  ## lane, modulo 65536." To remove: "subtract its lanes instead (modulo
  ## 65536)". The digest is "sha256(state)".

  @spec empty_state() :: binary()
  def empty_state, do: :binary.copy(<<0>>, @state_bytes)

  @doc """
  The element a record maps to: "the UTF-8 bytes of `{collection}/{rkey}/{record_cid}`".
  """
  @spec element(String.t(), String.t(), String.t()) :: String.t()
  def element(collection, rkey, record_cid),
    do: collection <> "/" <> rkey <> "/" <> record_cid

  @spec add_element(binary(), String.t()) :: binary()
  def add_element(state, element), do: fold_lanes(state, expand(element), &rem(&1 + &2, 65_536))

  @spec remove_element(binary(), String.t()) :: binary()
  def remove_element(state, element),
    do: fold_lanes(state, expand(element), &rem(&1 - &2, 65_536))

  @spec state_digest(binary()) :: binary()
  def state_digest(state), do: :crypto.hash(:sha256, state)

  defp expand(element), do: Blake3.hash(element, @state_bytes)

  # 1024 little-endian u16 lanes, combined pairwise with wraparound arithmetic.
  defp fold_lanes(state, expansion, combine),
    do: fold_lanes(state, expansion, combine, <<>>)

  defp fold_lanes(
         <<a::little-16, rest_a::binary>>,
         <<b::little-16, rest_b::binary>>,
         combine,
         acc
       ),
       do: fold_lanes(rest_a, rest_b, combine, <<acc::binary, combine.(a, b)::little-16>>)

  defp fold_lanes(<<>>, <<>>, _combine, acc), do: acc

  ## The commit context and MAC — proposal "Commit signature"
  ##
  ## context = "atproto-space-v1" || u16be(len(space)) || space || … for
  ## (space, author, rev, ikm); mac = HMAC-SHA256(HKDF-Expand(ikm, context, 32), hash)
  ## with "the 32-byte ikm used directly as the pseudorandom key with context
  ## as the info input. There is no extract step."

  @spec commit_context(String.t(), String.t(), String.t(), binary()) :: binary()
  def commit_context(space, author, rev, ikm) do
    Enum.reduce([space, author, rev, ikm], @domain_tag, fn field, acc ->
      acc <> <<byte_size(field)::unsigned-big-16>> <> field
    end)
  end

  @spec commit_mac(binary(), binary(), binary()) :: binary()
  def commit_mac(ikm, context, repo_hash) do
    :crypto.mac(:hmac, :sha256, hkdf_expand(ikm, context, 32), repo_hash)
  end

  # HKDF-Expand, RFC 5869 §2.3: T(i) = HMAC(PRK, T(i-1) || info || i),
  # with T(0) the empty string; OKM is the first L bytes. (One block whenever
  # L <= 32, which is the commit MAC's case — but the loop is the spec's.)
  defp hkdf_expand(prk, info, length) do
    block_count = div(length + 31, 32)
    expand_blocks(prk, info, block_count, 1, <<>>, <<>>)
  end

  defp expand_blocks(_prk, _info, n, i, _t, okm) when i > n, do: okm

  defp expand_blocks(prk, info, n, i, t, okm) do
    t_i = :crypto.mac(:hmac, :sha256, prk, t <> info <> <<i>>)
    expand_blocks(prk, info, n, i + 1, t_i, okm <> t_i)
  end

  ## Repo serialization — proposal "Repo serialization"
  ##
  ## "The CAR header declares two roots, in order: the signed commit … [and]
  ## the index — a DRISL (DAG-CBOR) map from "{collection}/{rkey}" to the
  ## record's CID, with keys in canonical DAG-CBOR map order (shortest key
  ## first, then bytewise). The record blocks follow the two roots, and MUST
  ## appear in the same order as their index entries."

  # Not named `record` — that would shadow the built-in type.
  @type space_record :: {collection :: String.t(), rkey :: String.t(), value :: term()}

  @doc """
  Serialize a repo as the two-root CAR. With `exclude_values: true` only the
  two roots are written (the index-only serving shape).
  """
  @spec serialize_repo(map(), [space_record()], keyword()) :: binary()
  def serialize_repo(commit, records, opts \\ []) do
    # The signedCommit's hash/ikm/sig/mac are lexicon `bytes` — DAG-CBOR byte
    # strings, not text — so they are tagged before encoding (see dag_cbor/1).
    commit_wire =
      Map.new(commit, fn
        {k, v} when k in ~w(hash ikm sig mac) -> {k, {:bytes, v}}
        {k, v} -> {k, v}
      end)

    by_path =
      Map.new(records, fn {collection, rkey, value} -> {collection <> "/" <> rkey, value} end)

    index = Map.new(by_path, fn {path, value} -> {path, content_cid(dag_cbor(value))} end)
    ordered_paths = canonical_key_order(Map.keys(index))

    commit_block = dag_cbor(commit_wire)
    commit_cid = content_cid(commit_block)
    index_block = dag_cbor(index)
    index_cid = content_cid(index_block)

    header = dag_cbor(%{"version" => 1, "roots" => [commit_cid, index_cid]})

    blocks =
      [{commit_cid, commit_block}, {index_cid, index_block}] ++
        if opts[:exclude_values] do
          []
        else
          Enum.map(ordered_paths, fn path ->
            cid = Map.fetch!(index, path)
            {cid, dag_cbor(Map.fetch!(by_path, path))}
          end)
        end

    iodata = [
      frame(IO.iodata_to_binary(header))
      | Enum.map(blocks, fn {cid, bytes} ->
          frame(cid_bytes(cid) <> IO.iodata_to_binary(bytes))
        end)
    ]

    IO.iodata_to_binary(iodata)
  end

  # "shortest key first, then bytewise" — the proposal's phrasing of canonical
  # DAG-CBOR map order.
  defp canonical_key_order(keys), do: Enum.sort_by(keys, &{byte_size(&1), &1})

  # A CIDv1 with the dag-cbor codec (0x71) and a sha2-256 multihash:
  # <<version, codec, 0x12, 0x20, digest>>.
  defp content_cid(bytes),
    do:
      {:cid,
       <<0x01, 0x71, 0x12, 0x20, :crypto.hash(:sha256, IO.iodata_to_binary(bytes))::binary>>}

  defp cid_bytes({:cid, bytes}), do: bytes

  # CAR v1 framing: a varint byte count followed by the counted bytes; the
  # header frame holds the header block, block frames hold <CID><data>.
  defp frame(bytes), do: [leb128(byte_size(bytes)), bytes]

  defp leb128(n) when n < 128, do: <<n>>
  defp leb128(n), do: <<1::size(1), rem(n, 128)::size(7), leb128(div(n, 128))::binary>>

  ## Minimal DAG-CBOR — the data model the index and records encode into:
  ## text-string map keys in canonical order, byte strings (major 2) distinct
  ## from text strings (major 3), minimal-length integer heads, tag 42 with the
  ## 0x00 multibase identity prefix for CID links.

  defp dag_cbor(%{} = map) do
    pairs =
      map
      |> Enum.map(fn {k, v} -> {to_string(k), v} end)
      |> Enum.sort_by(fn {k, _v} -> {byte_size(k), k} end)

    [
      head(5, length(pairs))
      | Enum.flat_map(pairs, fn {k, v} -> [dag_cbor(k), dag_cbor(v)] end)
    ]
  end

  defp dag_cbor(list) when is_list(list),
    do: [head(4, length(list)) | Enum.map(list, &dag_cbor/1)]

  defp dag_cbor(true), do: <<0xF5>>
  defp dag_cbor(false), do: <<0xF4>>

  # CID links: tag 42 over a byte string of 0x00 ++ raw CID.
  defp dag_cbor({:cid, _} = cid),
    do: [<<0xD8, 42>>, head(2, byte_size(cid_bytes(cid)) + 1), <<0x00>>, cid_bytes(cid)]

  # Lexicon `bytes` (the signedCommit's hash/ikm/sig/mac): a byte string.
  defp dag_cbor({:bytes, binary}), do: head(2, byte_size(binary)) |> iodata_with(binary)

  defp dag_cbor(binary) when is_binary(binary),
    do: head(3, byte_size(binary)) |> iodata_with(binary)

  defp dag_cbor(integer) when is_integer(integer) and integer >= 0, do: head(0, integer)

  defp dag_cbor(integer) when is_integer(integer) and integer < 0, do: head(1, -1 - integer)

  defp iodata_with(head_iodata, binary), do: [head_iodata, binary]

  # Minimal-length argument encoding, per core deterministic CBOR.
  defp head(major, n) when n < 24, do: <<major::size(3), n::size(5)>>
  defp head(major, n) when n < 0x100, do: <<major::size(3), 24::size(5), n::size(8)>>
  defp head(major, n) when n < 0x10000, do: <<major::size(3), 25::size(5), n::size(16)>>
  defp head(major, n) when n < 0x100000000, do: <<major::size(3), 26::size(5), n::size(32)>>

  defp head(major, n) when n < 0x10000000000000000,
    do: <<major::size(3), 27::size(5), n::size(64)>>
end
