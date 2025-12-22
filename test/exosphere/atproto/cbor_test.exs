defmodule Exosphere.ATProto.CBORTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CBOR, CID}

  test "encode/decode round-trip for maps (keys normalized to strings)" do
    input =
      %{b: 1}
      |> Map.put("a", 2)

    {:ok, bin} = CBOR.encode(input)
    assert {:ok, decoded} = CBOR.decode(bin)
    assert decoded == %{"a" => 2, "b" => 1}
  end

  test "encoding is deterministic regardless of input key order" do
    {:ok, bin1} = CBOR.encode(%{"b" => 1, "a" => 2})
    {:ok, bin2} = CBOR.encode(%{"a" => 2, "b" => 1})
    assert bin1 == bin2
  end

  test "floats are rejected" do
    assert {:error, :floats_not_allowed} = CBOR.encode(3.14)
  end

  test "CID links (tag 42) round-trip as CID structs" do
    cid = CID.create!(%{"hello" => "world"})
    {:ok, bin} = CBOR.encode(%{"ref" => cid})

    assert {:ok, %{"ref" => decoded_cid}} = CBOR.decode(bin)
    assert %CID{} = decoded_cid
    assert decoded_cid == cid
  end
end
