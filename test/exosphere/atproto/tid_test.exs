defmodule Exosphere.ATProto.TIDTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.TID

  test "generate/0 returns a base32-sortable 13-char tid" do
    tid = TID.generate()

    assert is_binary(tid)
    assert byte_size(tid) == 13
    assert tid =~ ~r/^[2-7a-z]{13}$/
    assert TID.valid?(tid)
  end

  test "generate_for/1 and to_datetime/1 round-trip microsecond timestamp" do
    dt = ~U[2024-01-15 12:30:45.123456Z]
    tid = TID.generate_for(dt)

    assert {:ok, decoded} = TID.to_datetime(tid)
    assert DateTime.to_unix(decoded, :microsecond) == DateTime.to_unix(dt, :microsecond)
  end

  test "compare/2 respects chronology (lexicographic order)" do
    dt1 = ~U[2024-01-01 00:00:00.000000Z]
    dt2 = ~U[2024-01-01 00:00:00.000001Z]

    tid1 = TID.generate_for(dt1)
    tid2 = TID.generate_for(dt2)

    assert tid1 < tid2
    assert TID.compare(tid1, tid2) == :lt
    assert TID.compare(tid2, tid1) == :gt
    assert TID.compare(tid1, tid1) == :eq
  end

  test "invalid tids are rejected" do
    assert TID.valid?("too-short") == false
    assert {:error, :invalid_tid} = TID.to_datetime("too-short")

    # invalid character: '1' is not in the alphabet
    bad = "1" <> String.duplicate("a", 12)
    assert TID.valid?(bad) == false
    assert {:error, :invalid_tid} = TID.to_datetime(bad)
  end

  test "valid?/1 enforces the restricted leading character" do
    # 'z' is a valid base32-sortable char but not allowed as the FIRST char
    # (the top bit of the 64-bit TID value must be 0).
    bad_first = "z" <> String.duplicate("a", 12)
    assert byte_size(bad_first) == 13
    assert TID.valid?(bad_first) == false

    # Every allowed leading character is accepted.
    for c <- ~c"234567abcdefghij" do
      assert TID.valid?(<<c>> <> String.duplicate("2", 12))
    end

    # A disallowed leading character ('k'..'z') is rejected.
    for c <- ~c"klmnopqrstuvwxyz" do
      refute TID.valid?(<<c>> <> String.duplicate("2", 12))
    end
  end
end
