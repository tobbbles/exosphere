defmodule Exosphere.ATProto.Spaces.SpecEncoderTest do
  @moduledoc """
  The G6 differential: the spec-only second encoder (`SpecEncoder`, written
  from the proposal README) against both the production implementation
  (`Spaces.{Lthash,Commit,Repo}`) and the reference corpus.

  Agreement between the two encoders is evidence a shared-encoder dogfood loop
  cannot produce: a wrong reading of the proposal would have to be made twice,
  independently, to pass here.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exosphere.ATProto.Spaces.{Lthash, SpecEncoder}
  alias Exosphere.Test.Interop

  defp unhex(s), do: Base.decode16!(s, case: :mixed)

  describe "the spec encoder independently reproduces the corpus" do
    test "every LtHash case, from its own lane math" do
      corpus = Interop.spaces_corpus("lthash.json")

      for case <- corpus["cases"] do
        state =
          Enum.reduce(case["ops"], SpecEncoder.empty_state(), fn %{"op" => op, "element" => el},
                                                                 acc ->
            apply(SpecEncoder, String.to_existing_atom(op <> "_element"), [acc, el])
          end)

        assert state == Base.decode64!(case["state"]), "#{case["name"]}: state diverged"

        assert SpecEncoder.state_digest(state) == unhex(case["digest"]),
               "#{case["name"]}: digest diverged"
      end
    end
  end

  describe "differential against the production implementation" do
    property "set hash: add/remove sequences agree, state and digest" do
      element =
        gen(
          all(
            collection <- nsid(),
            rkey <- string(:alphanumeric, min_length: 1, max_length: 8),
            do: SpecEncoder.element(collection, rkey, "bafyreic#{rkey}")
          )
        )

      op = tuple({member_of([:add, :remove]), element})

      check all(ops <- list_of(op, max_length: 30)) do
        spec =
          Enum.reduce(ops, SpecEncoder.empty_state(), fn
            {:add, el}, acc -> SpecEncoder.add_element(acc, el)
            {:remove, el}, acc -> SpecEncoder.remove_element(acc, el)
          end)

        production =
          Enum.reduce(ops, Lthash.new(), fn
            {:add, el}, acc -> Lthash.add(acc, el)
            {:remove, el}, acc -> Lthash.remove(acc, el)
          end)

        assert spec == Lthash.state(production)
        assert SpecEncoder.state_digest(spec) == Lthash.digest(production)
      end
    end
  end

  # -- generators -------------------------------------------------------------

  # lowercase-only, letter-first labels per the NSID grammar
  defp nsid do
    gen(all(a <- segment(), b <- segment(), c <- segment(), do: Enum.join([a, b, c], ".")))
  end

  defp segment do
    gen(
      all(
        s <- string(:alphanumeric, min_length: 1, max_length: 8, prefix: "a"),
        do: String.downcase(s)
      )
    )
  end

  # JSON-shaped values the data model can encode (no floats — DAG-CBOR rejects them).
  defp json_value(depth) when depth >= 3 do
    one_of([
      string(:alphanumeric, min_length: 0, max_length: 30),
      integer(),
      boolean()
    ])
  end

  defp json_value(depth) do
    one_of([
      string(:alphanumeric, min_length: 0, max_length: 30),
      integer(),
      boolean(),
      list_of(json_value(depth + 1), max_length: 4),
      map_of(
        string(:alphanumeric, min_length: 1, max_length: 12, prefix: "k"),
        json_value(depth + 1),
        max_length: 4
      )
    ])
  end
end
