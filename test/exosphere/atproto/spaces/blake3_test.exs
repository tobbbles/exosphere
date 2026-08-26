defmodule Exosphere.ATProto.Spaces.Blake3Test do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Spaces.Blake3

  # Official vectors from the BLAKE3 repo (input[i] = i % 251).
  @official_vectors [
    {0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
    {1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"},
    {2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"},
    {3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"},
    {63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"},
    {64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"},
    {65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"},
    {1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"},
    {1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"},
    {1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"},
    {2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"},
    {2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"},
    {3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"},
    {4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"},
    {8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"},
    {16_384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"},
    {102_400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085"}
  ]

  # From @noble/hashes (the library the atproto reference uses) at the exact
  # LtHash parameters: 2048-byte XOF of the reference test elements.
  @noble_xof_vectors [
    {"one", "d33fb48ab5adff26"},
    {"two", "dc770fff53f50835"}
  ]

  test "matches the official BLAKE3 vectors across chunk boundaries" do
    for {len, expected} <- @official_vectors do
      input = pattern(len)

      assert Blake3.hash(input, 32) |> Base.encode16(case: :lower) == expected,
             "vector mismatch at input length #{len}"
    end
  end

  test "extended output length is honored" do
    input = "an element string"

    for len <- [1, 31, 32, 33, 63, 64, 65, 128, 2047, 2048, 2049] do
      out = Blake3.hash(input, len)
      assert byte_size(out) == len
    end

    # XOF is a stream: prefixes agree at every length.
    full = Blake3.hash(input, 2048)
    assert binary_part(full, 0, 33) == Blake3.hash(input, 33)
  end

  test "matches @noble/hashes XOF at the LtHash parameters" do
    for {element, first8} <- @noble_xof_vectors do
      assert Blake3.hash(element, 2048) |> binary_part(0, 8) |> Base.encode16(case: :lower) ==
               first8
    end
  end

  # The BLAKE3 decision (pure Elixir, no new dependency): verification folds
  # one 2048-byte expansion per record per checkpoint — never per firehose
  # frame — so single-digit-millisecond expansions keep sync comfortably
  # interactive. This is a generous regression bound, not a bench target.
  test "element expansion stays in the interactive range" do
    element =
      "com.example.groupPost/3jwdwj2ctlk26/bafyreidhesplazc3hl7eado7q7kjtg6dijzsiusug74uay5vh4atxszqm4"

    {micros, _} = :timer.tc(fn -> Blake3.hash(element, 2048) end)
    assert micros < 50_000, "single expansion took #{micros / 1000}ms"

    {micros, _} = :timer.tc(fn -> for(_ <- 1..100, do: Blake3.hash(element, 2048)) end)
    assert micros < 3_000_000, "100 expansions took #{micros / 1000}ms"
  end

  defp pattern(0), do: <<>>

  defp pattern(len) do
    for i <- 0..(len - 1), into: <<>>, do: <<rem(i, 251)>>
  end
end
