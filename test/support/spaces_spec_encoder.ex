defmodule Exosphere.ATProto.Spaces.SpecEncoder do
  @moduledoc """
  Test-only second encoder for the spaces wire format — the ADR 0025 G6
  carve-out ("a test-only second encoder, written from the spec text by a
  different author, living only in the test suite").

  ## Provenance rule

  Every construction below was written from the **proposal 0016 README** at
  bluesky-social/proposals `0634c26` ("Commit digest", "Shared secret",
  "Authenticity headers", "Commit MAC", "Record MAC", "Repo serialization",
  "Space meta archive"), NOT from `Exosphere.ATProto.Spaces.*` and NOT from
  the reference TypeScript. Where the proposal defers to an external spec,
  that spec's text is the source: RFC 9180 §4.1 for the KEM framing, RFC 5869
  for HKDF, RFC 9651 for the header dictionaries, the DAG-CBOR/DRISL data
  model for encoding, and dasl.ing/star for the archive framing as the
  proposal restates it.

  The shared primitives are BLAKE3-XOF (through the NIF) and P-256 ECDH
  (Erlang `:crypto`): both are primitives rather than readings of the
  proposal, and each is pinned independently — BLAKE3 by the official
  vectors, the pure-Elixir `Blake3.Reference` differential and the corpus;
  the KEM by the RFC 9180 A.3.1 vector and the corpus.

  **This module is test-support only. It must never be imported from `lib/`.**
  """

  alias Exosphere.ATProto.Spaces.Blake3

  @state_bytes 2048

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

  ## Shared secret — proposal "Shared secret" (RFC 9180 §4.1 framing)
  ##
  ## dh = ECDH(syncer_private_key, author_public_key), "the 32-byte
  ## x-coordinate of the shared point"; keys = syncer_key_bytes ||
  ## author_key_bytes, both "0x04 || x || y"; prefix = "HPKE-v1" || "KEM" ||
  ## uint16be(0x0010); input = prefix || "eae_prk" || dh; info = uint16be(32)
  ## || prefix || "shared_secret" || keys; "Run HKDF with an empty salt and
  ## ask for 32 bytes of key material."

  @doc """
  The shared secret from a raw ECDH x-coordinate and both uncompressed public
  keys, syncer's first. (The ECDH itself is `:crypto`'s — a primitive, not a
  reading of the proposal.)
  """
  @spec shared_secret(binary(), binary(), binary()) :: binary()
  def shared_secret(dh, syncer_key_bytes, author_key_bytes) do
    prefix = "HPKE-v1" <> "KEM" <> <<0x00, 0x10>>
    input = prefix <> "eae_prk" <> dh
    info = <<0x00, 0x20>> <> prefix <> "shared_secret" <> syncer_key_bytes <> author_key_bytes
    hkdf(input, "", info, 32)
  end

  @doc "ECDH on P-256 (the x-coordinate), for computing `dh` above."
  @spec ecdh(binary(), binary()) :: binary()
  def ecdh(private_key, peer_public_uncompressed),
    do: :crypto.compute_key(:ecdh, peer_public_uncompressed, private_key, :secp256r1)

  # HKDF, RFC 5869: PRK = HMAC-Hash(salt, IKM) with an empty salt read as
  # HashLen zero bytes (§2.2), then the §2.3 expand loop.
  defp hkdf(ikm, salt, info, length) do
    salt = if salt == "", do: :binary.copy(<<0>>, 32), else: salt
    prk = :crypto.mac(:hmac, :sha256, salt, ikm)
    hkdf_expand(prk, info, length)
  end

  # HKDF-Expand, RFC 5869 §2.3: T(i) = HMAC(PRK, T(i-1) || info || i),
  # with T(0) the empty string; OKM is the first L bytes.
  defp hkdf_expand(prk, info, length) do
    block_count = div(length + 31, 32)
    okm = expand_blocks(prk, info, block_count, 1, <<>>, <<>>)
    binary_part(okm, 0, length)
  end

  defp expand_blocks(_prk, _info, n, i, _t, okm) when i > n, do: okm

  defp expand_blocks(prk, info, n, i, t, okm) do
    t_i = :crypto.mac(:hmac, :sha256, prk, t <> info <> <<i>>)
    expand_blocks(prk, info, n, i + 1, t_i, okm <> t_i)
  end

  ## Commit MAC — proposal "Commit MAC"
  ##
  ## context = "atproto-space-repo-v1" (protocol tag "{type}-v{ver}")
  ##    || uint16be(len(space)) || space || uint16be(len(repo)) || repo
  ##    || uint16be(len(rev)) || rev
  ## mac = HMAC-SHA256(shared_secret, context || data)
  ## "The string fields are UTF-8, each prefixed with its byte length as a
  ## big-endian uint16."

  @spec commit_context(String.t(), String.t(), String.t()) :: binary()
  def commit_context(space, repo, rev) do
    Enum.reduce([space, repo, rev], "atproto-space-repo-v1", fn field, acc ->
      acc <> <<byte_size(field)::unsigned-big-16>> <> field
    end)
  end

  @spec commit_mac(binary(), String.t(), String.t(), String.t(), binary()) :: binary()
  def commit_mac(shared_secret, space, repo, rev, data),
    do: :crypto.mac(:hmac, :sha256, shared_secret, commit_context(space, repo, rev) <> data)

  ## Record MAC — proposal "Record MAC"
  ##
  ## context = "atproto-space-record-v1" || uint16be(len(uri)) || uri
  ## mac = HMAC-SHA256(shared_secret, context || record_cid_bytes)

  @spec record_mac(binary(), String.t(), binary()) :: binary()
  def record_mac(shared_secret, uri, record_cid_bytes) do
    context = "atproto-space-record-v1" <> <<byte_size(uri)::unsigned-big-16>> <> uri
    :crypto.mac(:hmac, :sha256, shared_secret, context <> record_cid_bytes)
  end

  ## Authenticity headers — proposal "Authenticity headers"
  ##
  ## Atproto-Space-Want-Mac: type="atproto-space-repo", ver=1, key_share="did:key:…"
  ## Atproto-Space-Mac: type="atproto-space-repo", ver=1, mac=:<base64>:
  ## (RFC 9651 Dictionaries: Strings quoted, Integers bare, Byte Sequences in
  ## colons with padded base64, members joined by ", ").

  @spec want_mac_header(String.t(), String.t()) :: String.t()
  def want_mac_header(type, key_share),
    do: ~s(type="#{type}", ver=1, key_share="#{key_share}")

  @spec mac_header(String.t(), binary()) :: String.t()
  def mac_header(type, mac), do: ~s(type="#{type}", ver=1, mac=:#{Base.encode64(mac)}:)

  ## Repo serialization — proposal "Repo serialization"
  ##
  ## "[ magic | len | metadata ] [ 1 | len | path | len | record ] … [ 0 ]".
  ## "The magic bytes are 0x2A 0x6C 0x01 0x00. Each len is an unsigned varint
  ## giving the byte length of the following item. Each pair is preceded by a
  ## 0x01 byte, and the archive ends with a 0x00 byte." The metadata is "a
  ## DRISL map containing $type set to atproto-space-repo and all fields of
  ## the commit". Keys are "the UTF-8 encoding of a valid record path,
  ## {collection}/{rkey}", values "the record's canonical DRISL encoding", and
  ## "Records MUST appear in strict lexicographic order of the key bytes".

  # Not named `record` — that would shadow the built-in type.
  @type space_record :: {collection :: String.t(), rkey :: String.t(), value :: term()}

  @doc """
  Serialize a repo as an `atproto-space-repo` STAR archive. `commit` has the
  proposal's commit fields (`ver`, `repo`, `space`, `rev`, `data`).
  """
  @spec serialize_repo(map(), [space_record()]) :: binary()
  def serialize_repo(commit, records) do
    meta =
      commit
      |> Map.new(fn
        {"data", v} -> {"data", {:bytes, v}}
        pair -> pair
      end)
      |> Map.put("$type", "atproto-space-repo")

    pairs =
      records
      |> Enum.map(fn {collection, rkey, value} ->
        {collection <> "/" <> rkey, dag_cbor(value)}
      end)
      |> Enum.sort_by(&elem(&1, 0))

    star(meta, pairs)
  end

  @doc "The CID string of a record value, as folded into the set hash."
  @spec record_cid_string(term()) :: String.t()
  def record_cid_string(value), do: "b" <> base32(cid_bytes(content_cid(dag_cbor(value))))

  @doc "The binary CID of a record value (what the record MAC covers)."
  @spec record_cid_bytes(term()) :: binary()
  def record_cid_bytes(value), do: cid_bytes(content_cid(dag_cbor(value)))

  ## Space meta archive — proposal "Space meta archive"
  ##
  ## Metadata {"$type": "atproto-space-meta", "ver": 1, "space": …}; the body
  ## has three sections in order — "a single policy key", then policy state
  ## keys "structured like repository keys", then "one writer/{did} key per
  ## account in the writer set" carrying rev, data and spaceRev — and "within
  ## each section, keys MUST be in strict lexicographic order".

  @spec serialize_space_meta(String.t(), map(), [{String.t(), map()}], [map()]) :: binary()
  def serialize_space_meta(space, policy, policy_state, writers) do
    meta = %{"$type" => "atproto-space-meta", "ver" => 1, "space" => space}

    state_pairs =
      policy_state
      |> Enum.map(fn {key, value} -> {key, dag_cbor(value)} end)
      |> Enum.sort_by(&elem(&1, 0))

    writer_pairs =
      writers
      |> Enum.map(fn %{"did" => did} = w ->
        value = %{"rev" => w["rev"], "data" => {:bytes, w["data"]}, "spaceRev" => w["spaceRev"]}
        {"writer/" <> did, dag_cbor(value)}
      end)
      |> Enum.sort_by(&elem(&1, 0))

    star(meta, [{"policy", dag_cbor(policy)} | state_pairs] ++ writer_pairs)
  end

  defp star(meta, pairs) do
    IO.iodata_to_binary([
      <<0x2A, 0x6C, 0x01, 0x00>>,
      frame(IO.iodata_to_binary(dag_cbor(meta))),
      Enum.map(pairs, fn {key, value} ->
        [<<0x01>>, frame(key), frame(IO.iodata_to_binary(value))]
      end),
      <<0x00>>
    ])
  end

  # A CIDv1 with the dag-cbor codec (0x71) and a sha2-256 multihash:
  # <<version, codec, 0x12, 0x20, digest>>.
  defp content_cid(bytes),
    do:
      {:cid,
       <<0x01, 0x71, 0x12, 0x20, :crypto.hash(:sha256, IO.iodata_to_binary(bytes))::binary>>}

  defp cid_bytes({:cid, bytes}), do: bytes

  # Multibase "b": RFC 4648 base32, lowercase, unpadded.
  defp base32(bytes), do: bytes |> Base.encode32(case: :lower, padding: false)

  # A varint byte count followed by the counted bytes.
  defp frame(bytes), do: [leb128(byte_size(bytes)), bytes]

  defp leb128(n) when n < 128, do: <<n>>
  defp leb128(n), do: <<1::size(1), rem(n, 128)::size(7), leb128(div(n, 128))::binary>>

  ## Minimal DAG-CBOR (DRISL) — the data model metadata and records encode
  ## into: text-string map keys in canonical order (shortest first, then
  ## bytewise), byte strings (major 2) distinct from text strings (major 3),
  ## minimal-length integer heads, tag 42 with the 0x00 multibase identity
  ## prefix for CID links.
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

  # Lexicon `bytes` (a commit's data, a writer's data): a byte string.
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
