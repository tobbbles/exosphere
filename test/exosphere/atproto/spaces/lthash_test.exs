defmodule Exosphere.ATProto.Spaces.LthashTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exosphere.ATProto.Spaces.Lthash

  # Snapshot vectors from the reference implementation's test suite (generated
  # with @noble/hashes): they lock the lane math and the BLAKE3 expansion
  # together.
  @empty_digest "E5A00AA9991AC8A5EE3109844D84A55583BD20572AD3FFCD42792F3C36B183AD"
  @one_two_digest "AE05CB6D224379D9710C290C8529945C5B0E0FDE9EAD30B9699057CE701C63E7"

  test "starts as 2048 zero bytes" do
    assert Lthash.state(Lthash.new()) == :binary.copy(<<0>>, 2048)
    assert Lthash.empty?(Lthash.new())
  end

  test "digest vectors lock the algorithm" do
    assert Lthash.new() |> Lthash.digest() |> Base.encode16() == @empty_digest

    assert Lthash.new()
           |> Lthash.add("one")
           |> Lthash.add("two")
           |> Lthash.digest()
           |> Base.encode16() ==
             @one_two_digest
  end

  test "add then remove returns to the zero state" do
    h = Lthash.new() |> Lthash.add("a")
    refute Lthash.empty?(h)
    h = Lthash.remove(h, "a")
    assert Lthash.empty?(h)
    assert Lthash.equal?(h, Lthash.new())
  end

  test "is a multiset — a double add does not cancel out" do
    h = Lthash.new() |> Lthash.add("a") |> Lthash.add("a")
    refute Lthash.empty?(h)
    h = Lthash.remove(h, "a")
    assert Lthash.equal?(h, Lthash.new() |> Lthash.add("a"))
  end

  test "distinguishes different elements" do
    refute Lthash.equal?(Lthash.new() |> Lthash.add("a"), Lthash.new() |> Lthash.add("b"))
  end

  test "state round-trips for persistence" do
    h = Lthash.new() |> Lthash.add("a") |> Lthash.add("b")
    {:ok, resumed} = Lthash.from_state(Lthash.state(h))
    assert Lthash.equal?(resumed, h)

    # A resumed copy diverges without touching the original (staging a change).
    staged = Lthash.add(resumed, "c")
    assert Lthash.equal?(h, Lthash.new() |> Lthash.add("a") |> Lthash.add("b"))
    refute Lthash.equal?(staged, h)

    assert {:ok, empty} = Lthash.from_state(nil)
    assert Lthash.empty?(empty)
    assert {:error, :invalid_state} = Lthash.from_state(<<0, 0, 0>>)
  end

  property "order-independence: the state depends only on the set" do
    check all(
            elements <-
              list_of(string(:alphanumeric, min_length: 1, max_length: 12),
                min_length: 1,
                max_length: 20
              )
          ) do
      forward = Enum.reduce(elements, Lthash.new(), &Lthash.add(&2, &1))
      backward = Enum.reverse(elements) |> Enum.reduce(Lthash.new(), &Lthash.add(&2, &1))
      shuffled = Enum.shuffle(elements) |> Enum.reduce(Lthash.new(), &Lthash.add(&2, &1))

      assert Lthash.equal?(forward, backward)
      assert Lthash.equal?(forward, shuffled)
      assert Lthash.digest(forward) == Lthash.digest(shuffled)
    end
  end

  property "add-then-remove identity returns to the empty state" do
    check all(
            elements <-
              list_of(string(:alphanumeric, min_length: 1, max_length: 12),
                min_length: 1,
                max_length: 15
              )
          ) do
      unique = Enum.uniq(elements)

      h =
        unique
        |> Enum.reduce(Lthash.new(), &Lthash.add(&2, &1))
        |> then(fn hash -> Enum.reduce(unique, hash, &Lthash.remove(&2, &1)) end)

      assert Lthash.empty?(h)
    end
  end

  property "incremental fold equals batch fold (exactly — these are integers)" do
    check all(
            elements <-
              list_of(string(:alphanumeric, min_length: 1, max_length: 12),
                min_length: 2,
                max_length: 25
              )
          ) do
      {prefix, rest} = Enum.split(elements, div(length(elements), 2))

      incremental =
        prefix
        |> Enum.reduce(Lthash.new(), &Lthash.add(&2, &1))
        |> then(fn hash -> Enum.reduce(rest, hash, &Lthash.add(&2, &1)) end)

      batch = Enum.reduce(elements, Lthash.new(), &Lthash.add(&2, &1))

      assert Lthash.state(incremental) == Lthash.state(batch)
    end
  end
end
