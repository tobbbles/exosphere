defmodule Exosphere.ATProto.CARTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias Exosphere.ATProto.{CAR, CBOR, CID}

  test "decode/1 of empty binary returns empty map" do
    assert {:ok, %{}} = CAR.decode(<<>>)
  end

  test "decode/1 parses a minimal CAR with one block and get_block/2 works" do
    term = %{"hello" => "world"}
    cid = CID.create!(term)
    block_data = CBOR.encode!(term)
    cid_bytes = CID.to_bytes(cid)

    header = %{"version" => 1, "roots" => []}
    header_bin = CBOR.encode!(header)

    car =
      encode_leb128(byte_size(header_bin)) <>
        header_bin <>
        encode_leb128(byte_size(cid_bytes) + byte_size(block_data)) <>
        cid_bytes <>
        block_data

    assert {:ok, blocks} = CAR.decode(car)
    assert is_map(blocks)
    assert Map.get(blocks, cid) == term

    assert CAR.get_block(blocks, cid) == term
    assert CAR.get_block(blocks, CID.encode(cid)) == term
  end

  defp encode_leb128(int) when is_integer(int) and int >= 0 do
    do_encode_leb128(int, [])
    |> Enum.reverse()
    |> IO.iodata_to_binary()
  end

  defp do_encode_leb128(int, acc) when int < 0x80 do
    [<<int>> | acc]
  end

  defp do_encode_leb128(int, acc) do
    byte = band(int, 0x7F) ||| 0x80
    do_encode_leb128(int >>> 7, [<<byte>> | acc])
  end
end
