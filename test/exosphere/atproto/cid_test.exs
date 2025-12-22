defmodule Exosphere.ATProto.CIDTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.CID

  test "create/1 produces a CIDv1 dag-cbor sha2-256 and string round-trips" do
    {:ok, cid} = CID.create(%{"hello" => "world"})

    assert cid.version == 1
    assert cid.codec == :dag_cbor
    assert byte_size(cid.hash) == 32

    encoded = CID.encode(cid)
    assert is_binary(encoded)
    assert String.starts_with?(encoded, "b")

    assert {:ok, decoded} = CID.decode(encoded)
    assert decoded == cid
  end

  test "raw blob cid uses raw codec and bytes round-trip" do
    {:ok, cid} = CID.create_raw(<<1, 2, 3>>)
    assert cid.codec == :raw

    bytes = CID.to_bytes(cid)
    assert {:ok, decoded} = CID.from_bytes(bytes)
    assert decoded == cid
  end

  test "Jason encoding uses $link wrapper" do
    cid = CID.create!(%{"a" => 1})
    json = Jason.encode!(%{"ref" => cid})

    assert %{"ref" => %{"$link" => link}} = Jason.decode!(json)
    assert is_binary(link)
    assert String.starts_with?(link, "b")
  end

  test "decode rejects unsupported multibase prefixes" do
    assert {:error, :unsupported_multibase} = CID.decode("z" <> "abc")
  end
end
