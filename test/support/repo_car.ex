defmodule Exosphere.ATProto.TestRepoCar do
  @moduledoc false
  # Builds a complete, signed atproto repository CAR for offline tests:
  # record blocks -> MST nodes -> signed commit -> CARv1 bytes. Everything is
  # constructed with the library's own encoders, so verifying it exercises the
  # same code paths as a real repository archive.

  alias Exosphere.ATProto.{CBOR, CID, Crypto, MST, TID}

  @did "did:plc:44ybard66vv44zksje25o7dz"

  @default_paths [
    "com.example.post/3jzfcijpj2z2a",
    "com.example.post/3jzfcijpj3z2a",
    "com.example.post/3jzfcijpj4z2a"
  ]

  # Returns:
  #
  #   %{
  #     car: binary(),                    # complete CARv1 archive
  #     commit: map(),                    # decoded commit object (incl. "sig")
  #     commit_cid: %CID{},
  #     root: %CID{},                     # MST root (== commit["data"])
  #     records: %{path => %CID{}},       # the repository record set
  #     node_blocks: %{CID => binary()},  # encoded MST node blocks
  #     public_key: binary()
  #   }
  def build(opts \\ []) do
    paths = Keyword.get(opts, :paths, @default_paths)
    curve = Keyword.get(opts, :curve, :secp256k1)
    did = Keyword.get(opts, :did, @did)

    {records, record_blocks} =
      Map.new(paths, fn path ->
        cid = CID.create!(%{"$type" => "com.example.post", "text" => "hello " <> path})
        {path, cid}
      end)
      |> records_and_blocks()

    {:ok, root, node_blocks} = MST.build(records)

    {:ok, %{private_key: priv, public_key: pub}} = Crypto.generate_keypair(curve)

    unsigned = %{"did" => did, "data" => root, "rev" => TID.generate(), "prev" => nil}
    {:ok, unsigned_bytes} = CBOR.encode(unsigned)
    {:ok, sig} = Crypto.sign(unsigned_bytes, priv, curve)
    commit = Map.put(unsigned, "sig", sig)

    commit_cid = CID.create!(commit)
    commit_bytes = CBOR.encode!(commit)

    blocks =
      record_blocks
      |> Map.merge(node_blocks)
      |> Map.put(commit_cid, commit_bytes)

    block_entries =
      blocks
      |> Enum.sort_by(fn {cid, _} -> to_string(cid) end)
      |> Enum.map(fn {cid, data} -> car_block(CID.to_bytes(cid), data) end)
      |> IO.iodata_to_binary()

    header = %{"v" => 1, "roots" => [commit_cid]}

    %{
      car: car_with_header(header, block_entries),
      commit: commit,
      commit_cid: commit_cid,
      root: root,
      records: records,
      node_blocks: node_blocks,
      public_key: pub
    }
  end

  # Pair the path=>CID record map with the matching CID=>encoded-bytes blocks
  # (the encoder is deterministic, so the bytes hash back to each CID).
  defp records_and_blocks(records) do
    blocks =
      Map.new(records, fn {path, cid} ->
        {cid, CBOR.encode!(%{"$type" => "com.example.post", "text" => "hello " <> path})}
      end)

    {records, blocks}
  end

  defp car_block(cid_bytes, data) do
    entry = cid_bytes <> data
    varint(byte_size(entry)) <> entry
  end

  defp car_with_header(header, blocks_binary) do
    header_bytes = CBOR.encode!(header)
    varint(byte_size(header_bytes)) <> header_bytes <> blocks_binary
  end

  defp varint(n) when n < 128, do: <<n>>
  defp varint(n), do: <<1::1, Integer.mod(n, 128)::7, varint(div(n, 128))::binary>>
end
