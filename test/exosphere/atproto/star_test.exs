defmodule Exosphere.ATProto.StarTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Star

  @fixtures Path.expand("../../fixtures/star", __DIR__)
  @valid @fixtures |> Path.join("valid-star-fixtures.json") |> File.read!() |> Jason.decode!()
  @invalid @fixtures |> Path.join("invalid-star-fixtures.json") |> File.read!() |> Jason.decode!()

  defp unhex(hex), do: Base.decode16!(hex, case: :mixed)

  test "every valid interop archive decodes to its recorded meta and pairs" do
    for fixture <- @valid do
      star = unhex(fixture["star_hex"])

      expected_pairs =
        Enum.map(fixture["decoded"]["pairs"], &{unhex(&1["key_hex"]), unhex(&1["value_hex"])})

      assert {:ok, %{meta: meta, pairs: pairs}} = Star.decode(star), fixture["comment"]
      assert meta == fixture["decoded"]["meta"], fixture["comment"]
      assert pairs == expected_pairs, fixture["comment"]
    end
  end

  test "every valid interop archive re-encodes to the same bytes" do
    for fixture <- @valid do
      star = unhex(fixture["star_hex"])

      pairs =
        Enum.map(fixture["decoded"]["pairs"], &{unhex(&1["key_hex"]), unhex(&1["value_hex"])})

      assert Star.encode(fixture["decoded"]["meta"], pairs) == star, fixture["comment"]
    end
  end

  test "every invalid interop archive is rejected" do
    for fixture <- @invalid do
      assert {:error, _} = Star.decode(unhex(fixture["star_hex"])), fixture["comment"]
    end
  end

  test "limits are checked before a frame is read" do
    star = Star.encode(%{"$type" => "t"}, [{"key", String.duplicate("v", 100)}])

    assert {:ok, _} = Star.decode(star, max_value_length: 100)
    assert {:error, {:length_exceeds_limit, :value}} = Star.decode(star, max_value_length: 99)
    assert {:error, {:length_exceeds_limit, :key}} = Star.decode(star, max_key_length: 2)
    assert {:error, {:length_exceeds_limit, :meta}} = Star.decode(star, max_meta_length: 3)
  end

  test "byte-string metadata survives the canonical round trip" do
    meta = %{"$type" => "t", "data" => %CBOR.Tag{tag: :bytes, value: <<1, 2, 3>>}}
    assert {:ok, %{meta: %{"data" => <<1, 2, 3>>}}} = Star.decode(Star.encode(meta, []))
  end

  test "varints are shortest-form LEB128" do
    assert Star.encode_varint(0) == <<0>>
    assert Star.encode_varint(127) == <<127>>
    assert Star.encode_varint(128) == <<0x80, 0x01>>
    assert Star.encode_varint(300) == <<0xAC, 0x02>>
  end
end
