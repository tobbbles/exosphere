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

  test "map keys use RFC 8949 length-first ordering, not pure bytewise" do
    # Bytewise: "aa" < "b". Length-first: "b" (len 1) < "aa" (len 2).
    {:ok, bin} = CBOR.encode(%{"b" => 1, "aa" => 2})
    assert bin == <<0xA2, 0x61, ?b, 1, 0x62, ?a, ?a, 2>>
  end

  test "produces the canonical DAG-CBOR vector for {hello: world}" do
    {:ok, bin} = CBOR.encode(%{"hello" => "world"})
    assert bin == <<0xA1, 0x65, "hello", 0x65, "world">>
  end

  test "CID links are encoded as byte strings (major type 2), per DAG-CBOR" do
    cid = CID.create!(%{"x" => 1})
    {:ok, bin} = CBOR.encode(%{"ref" => cid})
    # 0xA1 map(1), 0x63 "ref", 0xD8 0x2A tag(42), 0x58 0x25 byte-string(37)
    assert <<0xA1, 0x63, "ref", 0xD8, 42, 0x58, 0x25, 0x00, _rest::binary>> = bin
  end

  test "decodes real (byte-string) CID links produced by other implementations" do
    cid = CID.create!(%{"x" => 1})
    cid_bytes = <<0x00>> <> CID.to_bytes(cid)
    link_tag = %Elixir.CBOR.Tag{tag: 42, value: %Elixir.CBOR.Tag{tag: :bytes, value: cid_bytes}}
    # Hand-build a map whose CID link is a byte string, as real atproto data is.
    real = <<0xA1, 0x63, "ref">> <> Elixir.CBOR.encode(link_tag)

    assert {:ok, %{"ref" => decoded}} = CBOR.decode(real)
    assert decoded == cid
  end

  describe "int64 range" do
    test "encodes the int64 bounds as plain major-type 0/1 integers" do
      assert {:ok, <<0x1B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF>>} =
               CBOR.encode(9_223_372_036_854_775_807)

      assert {:ok, <<0x3B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF>>} =
               CBOR.encode(-9_223_372_036_854_775_808)
    end

    test "refuses integers outside int64 instead of emitting a bignum" do
      for n <- [2 ** 63, 2 ** 64, 2 ** 100, -(2 ** 63) - 1, -(2 ** 100)] do
        assert {:error, :integer_out_of_range} = CBOR.encode(n)
        assert {:error, :integer_out_of_range} = CBOR.encode(%{"a" => [n]})
      end
    end

    test "encode!/1 raises for them (encode/1 is the non-raising path)" do
      assert_raise ArgumentError, fn -> CBOR.encode!(2 ** 64) end
    end
  end

  describe "decode_links/1" do
    test "keeps byte strings as byte strings so re-encoding is identical" do
      cid = CID.decode!("bafyreidykglsfhoixmivffc5uwhcgshx4j465xwqntbmu43nb2dzqwfvae")
      value = %{"b" => %Elixir.CBOR.Tag{tag: :bytes, value: "hello"}, "l" => cid}
      {:ok, bin} = CBOR.encode(value)
      {:ok, raw, ""} = Elixir.CBOR.decode(bin)

      kept = CBOR.decode_links(raw)
      assert kept == value
      assert {:ok, ^bin} = CBOR.encode(kept)

      # transform_links/1 flattens bytes, which re-encode as a text string.
      flattened = CBOR.transform_links(raw)
      assert flattened["b"] == "hello"
      refute CBOR.encode!(flattened) == bin
    end
  end
end
