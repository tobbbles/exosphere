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

  alias Exosphere.ATProto.{CID, Crypto}
  alias Exosphere.ATProto.Spaces.{Commit, Lthash, Repo, SpecEncoder}
  alias Exosphere.Test.Interop

  @signed_commit Interop.spaces_corpus("signed-commit.json")
  @repo_car Interop.spaces_corpus("repo-car.json")

  # A pinned ikm so the CAR differential's commits are byte-deterministic.
  @ikm Base.decode16!("2F9A1B77C11E4F0FDE13B8A29D1C47E56A33F2AC1D0E7B44C9A2F6B3D5E8F701")

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

    test "every commit context and MAC" do
      for variant <- @signed_commit["variants"] do
        %{"space" => space, "author" => author, "rev" => rev} = variant["ctx"]
        ikm = unhex(variant["ikm"])

        assert SpecEncoder.commit_context(space, author, rev, ikm) == unhex(variant["ctxBytes"])

        assert SpecEncoder.commit_mac(
                 ikm,
                 unhex(variant["ctxBytes"]),
                 unhex(variant["commit"]["hash"])
               ) ==
                 unhex(variant["commit"]["mac"])
      end
    end

    test "the whole two-root CAR, full and index-only" do
      records = Enum.map(@repo_car["records"], &{&1["collection"], &1["rkey"], &1["record"]})
      commit = wire_commit(@repo_car["commit"])

      assert SpecEncoder.serialize_repo(commit, records) == Base.decode64!(@repo_car["car"])

      assert SpecEncoder.serialize_repo(commit, records, exclude_values: true) ==
               Base.decode64!(@repo_car["carIndexOnly"])
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

    property "commit context: byte-identical for arbitrary fields" do
      check all(
              space <- string(:printable, min_length: 0, max_length: 200),
              author <- string(:printable, min_length: 0, max_length: 100),
              rev <- string(:alphanumeric, min_length: 1, max_length: 13),
              ikm <- binary(min_length: 32, max_length: 32)
            ) do
        assert SpecEncoder.commit_context(space, author, rev, ikm) ==
                 Commit.encode_ctx(%{space: space, author: author, rev: rev}, ikm)
      end
    end

    property "commit MAC: byte-identical inside a real sign/verify cycle" do
      {:ok, %{private_key: priv, public_key: pub}} = Crypto.generate_keypair(:secp256k1)

      check all(
              elements <-
                list_of(string(:alphanumeric, min_length: 1, max_length: 20),
                  min_length: 0,
                  max_length: 15
                ),
              ikm <- binary(min_length: 32, max_length: 32)
            ) do
        hash = Enum.reduce(elements, Lthash.new(), &Lthash.add(&2, &1))
        ctx = %{space: "at://did:plc:s/space/t/k", author: "did:plc:a", rev: "3kbcq3p7ad2c2"}

        assert {:ok, commit} = Commit.sign(hash, ctx, priv, :secp256k1, ikm: ikm)

        assert SpecEncoder.commit_mac(
                 ikm,
                 SpecEncoder.commit_context(ctx.space, ctx.author, ctx.rev, ikm),
                 commit["hash"]
               ) == commit["mac"]

        assert :ok = Commit.verify(commit, ctx, pub, :secp256k1)
      end
    end

    property "repo CAR: byte-identical serialization over random record sets" do
      {:ok, %{private_key: priv}} = Crypto.generate_keypair(:secp256k1)

      record =
        gen(
          all(
            collection <- nsid(),
            rkey <- string(:alphanumeric, min_length: 1, max_length: 12),
            value <- json_value(0),
            do: {collection, rkey, value}
          )
        )

      check all(
              records <-
                uniq_list_of(record,
                  min_length: 0,
                  max_length: 12,
                  uniq_fun: fn {c, r, _} -> {c, r} end
                )
            ) do
        hash =
          Enum.reduce(records, Lthash.new(), fn {c, r, v}, acc ->
            Commit.add_record(acc, c, r, CID.encode(CID.create!(v)))
          end)

        ctx = %{
          space: "at://did:plc:s/space/com.example.t/default",
          author: "did:plc:a",
          rev: "3kbcq3p7ad2c2"
        }

        assert {:ok, commit} = Commit.sign(hash, ctx, priv, :secp256k1, ikm: @ikm)

        for exclude_values <- [false, true], input <- [records, Enum.reverse(records)] do
          assert SpecEncoder.serialize_repo(commit, input, exclude_values: exclude_values) ==
                   Repo.serialize(commit, input, exclude_values: exclude_values)
        end
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

  defp wire_commit(commit) do
    Map.new(commit, fn
      {k, v} when k in ~w(hash ikm sig mac) -> {k, unhex(v)}
      {k, v} -> {k, v}
    end)
  end
end
