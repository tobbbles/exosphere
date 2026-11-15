defmodule Exosphere.ATProto.Spaces.SpecEncoder do
  @moduledoc """
  Test-only second encoder for the spaces wire format — the ADR 0025 G6
  carve-out ("a test-only second encoder, written from the spec text by a
  different author, living only in the test suite").

  ## Provenance rule

  Every construction below was written from the **proposal 0016 README** at
  bluesky-social/proposals `0634c26` ("Commit digest", "Repo serialization",
  "Space meta archive") and, for the November 12 changes, the proposal's
  restatement in the alpha migration notes (atproto `d4def6e`,
  `alpha-migrations/prompt-11-12-26.md` sections 6a–6c), NOT from
  `Exosphere.ATProto.Spaces.*` and NOT from the reference TypeScript. Where
  the proposal defers to an external spec, that spec's text is the source:
  RFC 9180 §4, §4.1, §5.1 and §5.3 for the HPKE secret export, RFC 5869 for
  HKDF, RFC 9651 for the header dictionaries, RFC 9421 §2.5 and §3.3.3 for
  the signature base and `hmac-sha256`, the DAG-CBOR/DRISL data model for
  encoding, and dasl.ing/star for the archive framing as the proposal
  restates it.

  The shared primitives are BLAKE3-XOF (through the NIF), P-256 ECDH and
  HMAC-SHA256 (Erlang `:crypto`): all are primitives rather than readings of
  the proposal, and each is pinned independently — BLAKE3 by the official
  vectors, the pure-Elixir `Blake3.Reference` differential and the corpus;
  the HPKE export by the CFRG export-only DHKEM(P-256) vector and atproto's
  Go-computed `atproto-mac` vector.

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

  ## Shared secret — proposal "Shared secret" (November 12: HPKE secret
  ## export), from the RFC 9180 text
  ##
  ## "SendExportBase(author_kem_public_key, info="atproto-mac",
  ## exporter_context="", L=32)" in base mode with DHKEM(P-256, HKDF-SHA256)
  ## (0x0010), HKDF-SHA256 (0x0001) and the Export-only AEAD (0xFFFF). The
  ## steps, from RFC 9180:
  ##
  ##   §4:   LabeledExtract(salt, label, ikm) =
  ##           Extract(salt, "HPKE-v1" || suite_id || label || ikm)
  ##         LabeledExpand(prk, label, info, L) =
  ##           Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L)
  ##   §4.1: DHKEM, suite_id = "KEM" || I2OSP(kem_id, 2):
  ##           eae_prk = LabeledExtract("", "eae_prk", dh)
  ##           shared_secret = LabeledExpand(eae_prk, "shared_secret",
  ##                                         enc || pkRm, Nsecret = 32)
  ##         where dh is the ECDH x-coordinate and enc, pkRm are the
  ##         uncompressed points (SerializePublicKey, §7.1.1).
  ##   §5.1: KeySchedule, suite_id = "HPKE" || I2OSP(kem_id, 2) ||
  ##         I2OSP(kdf_id, 2) || I2OSP(aead_id, 2), mode_base = 0x00, empty psk:
  ##           psk_id_hash = LabeledExtract("", "psk_id_hash", "")
  ##           info_hash = LabeledExtract("", "info_hash", info)
  ##           key_schedule_context = mode || psk_id_hash || info_hash
  ##           secret = LabeledExtract(shared_secret, "secret", psk = "")
  ##           exporter_secret = LabeledExpand(secret, "exp",
  ##                                           key_schedule_context, Nh = 32)
  ##   §5.3: Export(exporter_context, L) =
  ##           LabeledExpand(exporter_secret, "sec", exporter_context, L)

  @kem_suite "KEM" <> <<0x00, 0x10>>
  @hpke_suite "HPKE" <> <<0x00, 0x10, 0x00, 0x01, 0xFF, 0xFF>>

  @doc """
  The secret HPKE exports in base mode for this suite, from the raw ECDH
  x-coordinate `dh`, the uncompressed `enc` (the syncer's ephemeral public
  key) and `pk_r` (the author's KEM public key), with `info`, the exporter
  context and the length. (The ECDH itself is `:crypto`'s — a primitive, not
  a reading of the spec.)
  """
  @spec export_secret(binary(), binary(), binary(), binary(), binary(), pos_integer()) ::
          binary()
  def export_secret(dh, enc, pk_r, info, exporter_context, length) do
    eae_prk = labeled_extract("", @kem_suite, "eae_prk", dh)
    shared_secret = labeled_expand(eae_prk, @kem_suite, "shared_secret", enc <> pk_r, 32)

    psk_id_hash = labeled_extract("", @hpke_suite, "psk_id_hash", "")
    info_hash = labeled_extract("", @hpke_suite, "info_hash", info)
    key_schedule_context = <<0x00>> <> psk_id_hash <> info_hash
    secret = labeled_extract(shared_secret, @hpke_suite, "secret", "")
    exporter_secret = labeled_expand(secret, @hpke_suite, "exp", key_schedule_context, 32)

    labeled_expand(exporter_secret, @hpke_suite, "sec", exporter_context, length)
  end

  @doc "The MAC secret: `info` \"atproto-mac\", an empty exporter context, 32 bytes."
  @spec mac_secret(binary(), binary(), binary()) :: binary()
  def mac_secret(dh, enc, pk_r), do: export_secret(dh, enc, pk_r, "atproto-mac", "", 32)

  @doc "ECDH on P-256 (the x-coordinate), for computing `dh` above."
  @spec ecdh(binary(), binary()) :: binary()
  def ecdh(private_key, peer_public_uncompressed),
    do: :crypto.compute_key(:ecdh, peer_public_uncompressed, private_key, :secp256r1)

  defp labeled_extract(salt, suite_id, label, ikm),
    do: hkdf_extract(salt, "HPKE-v1" <> suite_id <> label <> ikm)

  defp labeled_expand(prk, suite_id, label, info, length),
    do: hkdf_expand(prk, <<length::16>> <> "HPKE-v1" <> suite_id <> label <> info, length)

  # HKDF-Extract, RFC 5869 §2.2: PRK = HMAC-Hash(salt, IKM), an empty salt
  # read as HashLen zero bytes.
  defp hkdf_extract(salt, ikm) do
    salt = if salt == "", do: :binary.copy(<<0>>, 32), else: salt
    :crypto.mac(:hmac, :sha256, salt, ikm)
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

  ## MACs — proposal "Authenticity headers" (November 12: HTTP Message
  ## Signatures), with RFC 9651 for the field syntax and RFC 9421 for the
  ## signature
  ##
  ## Request (6b):  Accept-Signature: mac=("atproto-space-commit";sf);keyid="did:key:…";tag="atproto-space-commit"
  ## Response (6c): Atproto-Space-Commit: ver=1, repo="…", space="…", rev="…", data=:<base64>:
  ##                Atproto-Space-Record: uri="…", cid="…"
  ##                Signature-Input: mac=<the requested inner list and parameters>
  ##                Signature: mac=:<base64>:
  ##
  ## RFC 9651 §4.1: Dictionary members joined by ", ", Strings in double
  ## quotes with `"` and `\` backslash-escaped, Integers bare, Byte Sequences
  ## as `:` padded base64 `:`. RFC 9421 §2.5: the signature base is one line
  ## per covered component, `"name";sf: <canonical value>`, then
  ## `"@signature-params": <inner list and parameters>`, joined by LF, no
  ## trailing LF. §3.3.3: hmac-sha256 is HMAC-SHA256 keyed by the shared
  ## secret over the base.

  @doc "The `Accept-Signature` value requesting a MAC for `profile` under `label`."
  @spec accept_signature(String.t(), String.t(), String.t()) :: String.t()
  def accept_signature(label, profile, key_share),
    do: label <> "=" <> signature_params(profile, key_share)

  @doc "The inner list and parameters a host signs under (the request's, as given)."
  @spec signature_params(String.t(), String.t()) :: String.t()
  def signature_params(profile, key_share),
    do: ~s|("#{profile}";sf);keyid=#{sf_string(key_share)};tag=#{sf_string(profile)}|

  @doc "The `Atproto-Space-Commit` header for a commit's fields."
  @spec commit_header(integer(), String.t(), String.t(), String.t(), binary()) :: String.t()
  def commit_header(ver, repo, space, rev, data) do
    "ver=#{ver}, repo=#{sf_string(repo)}, space=#{sf_string(space)}, rev=#{sf_string(rev)}, " <>
      "data=:#{Base.encode64(data)}:"
  end

  @doc "The `Atproto-Space-Record` header for a record's URI and CID string."
  @spec record_header(String.t(), String.t()) :: String.t()
  def record_header(uri, cid), do: "uri=#{sf_string(uri)}, cid=#{sf_string(cid)}"

  @doc "The RFC 9421 signature base over one `sf`-flagged covered header."
  @spec signature_base(String.t(), String.t(), String.t()) :: String.t()
  def signature_base(header_name, header_value, signature_params),
    do: ~s|"#{header_name}";sf: #{header_value}\n"@signature-params": #{signature_params}|

  @doc "HMAC-SHA256 over a signature base (`hmac-sha256`, RFC 9421 §3.3.3)."
  @spec mac(binary(), String.t()) :: binary()
  def mac(shared_secret, base), do: :crypto.mac(:hmac, :sha256, shared_secret, base)

  @doc "The `Signature` value for a MAC under `label`."
  @spec signature(String.t(), binary()) :: String.t()
  def signature(label, mac), do: "#{label}=:#{Base.encode64(mac)}:"

  defp sf_string(string) do
    escaped = string |> String.replace("\\", "\\\\") |> String.replace("\"", "\\\"")
    "\"" <> escaped <> "\""
  end

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

  @doc "The binary CID of a record value."
  @spec record_cid_bytes(term()) :: binary()
  def record_cid_bytes(value), do: cid_bytes(content_cid(dag_cbor(value)))

  ## Space meta archive — proposal "Space meta archive"
  ##
  ## Metadata {"$type": "atproto-space-meta", "ver": 1, "space": …}; the body
  ## has three sections in order — "a single policy key", then policy state
  ## keys "structured like repository keys", then "one writer/{did} key per
  ## account in the writer set" carrying the repo revision, data and spaceRev
  ## — and "within each section, keys MUST be in strict lexicographic order".
  ##
  ## The proposal text (main at `0634c26`, and its open lexicon-refactor PR at
  ## `2d1ca30`) still calls the repo revision `rev`. The atproto
  ## `atproto-spaces-cleanup` branch (`4037310`) keys it `repoRev`, matching
  ## `listWriters#repo`. No prose names the key, so this one field follows the
  ## upstream `listWriters` lexicon's field name rather than the README.

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
        value = %{
          "repoRev" => w["repoRev"],
          "data" => {:bytes, w["data"]},
          "spaceRev" => w["spaceRev"]
        }

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
