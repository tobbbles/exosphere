defmodule Exosphere.ATProto.Spaces.SpecEncoderTest do
  @moduledoc """
  The G6 differential: the spec-only second encoder (`SpecEncoder`, written
  from the proposal README) against both the production implementation
  (`Spaces.{Lthash,Kem,Mac,Repo}`) and the reference corpus.

  Agreement between the two encoders is evidence a shared-encoder dogfood loop
  cannot produce: a wrong reading of the proposal would have to be made twice,
  independently, to pass here.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Exosphere.ATProto.{CID, Crypto}
  alias Exosphere.ATProto.Spaces.{Kem, Lthash, Mac, Repo, SpecEncoder}
  alias Exosphere.Test.Interop

  defp unhex(s), do: Base.decode16!(s, case: :mixed)

  @commit_mac Interop.spaces_corpus("commit-mac.json")
  @repo_star Interop.spaces_corpus("repo-star.json")
  @space_meta Interop.spaces_corpus("space-meta.json")

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

    test "every KEM shared secret, from its own HKDF over :crypto's ECDH" do
      author = @commit_mac["kem"]["author"]

      for vector <- @commit_mac["kem"]["vectors"] do
        eph = unhex(vector["ephemeralPrivateKey"])
        dh = SpecEncoder.ecdh(eph, unhex(author["publicKeyUncompressed"]))

        assert SpecEncoder.shared_secret(
                 dh,
                 unhex(vector["ephemeralPublicKeyUncompressed"]),
                 unhex(author["publicKeyUncompressed"])
               ) == unhex(vector["sharedSecret"])
      end
    end

    test "every commit context, MAC and header" do
      for variant <- @commit_mac["commits"] do
        %{"space" => space, "repo" => repo, "rev" => rev, "data" => data} = variant["commit"]
        secret = unhex(variant["sharedSecret"])
        mac = SpecEncoder.commit_mac(secret, space, repo, rev, unhex(data))

        assert mac == unhex(variant["mac"]), "#{variant["name"]}: MAC diverged"
        assert SpecEncoder.mac_header("atproto-space-repo", mac) == variant["macHeader"]

        key_share = Enum.at(@commit_mac["kem"]["vectors"], variant["kemVector"])["keyShare"]

        assert SpecEncoder.want_mac_header("atproto-space-repo", key_share) ==
                 variant["wantMacHeader"]
      end
    end

    test "every record MAC, over its own CID of the value" do
      for variant <- @commit_mac["records"] do
        secret =
          unhex(Enum.at(@commit_mac["kem"]["vectors"], variant["kemVector"])["sharedSecret"])

        cid_bytes = SpecEncoder.record_cid_bytes(variant["value"])
        assert cid_bytes == unhex(variant["cidBytes"])
        assert SpecEncoder.record_cid_string(variant["value"]) == variant["cid"]
        assert SpecEncoder.record_mac(secret, variant["uri"], cid_bytes) == unhex(variant["mac"])
      end
    end

    test "the repo STAR archive, populated and empty" do
      records = Enum.map(@repo_star["records"], &{&1["collection"], &1["rkey"], &1["record"]})
      commit = Map.update!(@repo_star["commit"], "data", &unhex/1)

      assert SpecEncoder.serialize_repo(commit, records) == Base.decode64!(@repo_star["star"])

      empty = Map.update!(@repo_star["empty"]["commit"], "data", &unhex/1)
      assert SpecEncoder.serialize_repo(empty, []) == Base.decode64!(@repo_star["empty"]["star"])
    end

    test "the space meta archive" do
      archive = @space_meta["archive"]
      state = Enum.map(archive["policyState"], &{&1["key"], &1["value"]})
      writers = Enum.map(archive["writers"], &Map.update!(&1, "data", fn d -> unhex(d) end))

      assert SpecEncoder.serialize_space_meta(archive["space"], archive["policy"], state, writers) ==
               Base.decode64!(@space_meta["star"])
    end
  end

  describe "differential against the production implementation" do
    property "commit MAC: byte-identical for arbitrary fields and secrets" do
      check all(
              space <- string(:printable, min_length: 1, max_length: 600),
              repo <- string(:alphanumeric, min_length: 1, max_length: 64),
              rev <- string(:alphanumeric, length: 13),
              data <- binary(length: 32),
              secret <- binary(length: 32)
            ) do
        commit = %{"ver" => 1, "space" => space, "repo" => repo, "rev" => rev, "data" => data}

        assert SpecEncoder.commit_mac(secret, space, repo, rev, data) ==
                 Mac.commit_mac(secret, commit)

        assert SpecEncoder.commit_context(space, repo, rev) ==
                 Mac.commit_context(space, repo, rev)
      end
    end

    property "record MAC: byte-identical over arbitrary URIs and values" do
      check all(
              uri <- string(:printable, min_length: 1, max_length: 300),
              value <- map_of(string(:alphanumeric, min_length: 1, max_length: 8), json_value(1)),
              secret <- binary(length: 32)
            ) do
        cid = CID.create!(value)
        assert SpecEncoder.record_cid_bytes(value) == CID.to_bytes(cid)

        assert SpecEncoder.record_mac(secret, uri, CID.to_bytes(cid)) ==
                 Mac.record_mac(secret, uri, CID.to_bytes(cid))
      end
    end

    property "KEM: the second derivation agrees with Kem.encapsulate/2" do
      check all(seed <- binary(length: 32)) do
        {:ok, author} = Crypto.generate_keypair(:p256)
        eph = :crypto.hash(:sha256, seed)
        {:ok, author_full} = Crypto.decompress(author.public_key, :p256)
        {eph_pub, _} = :crypto.generate_key(:ecdh, :secp256r1, eph)

        expected =
          SpecEncoder.shared_secret(SpecEncoder.ecdh(eph, author_full), eph_pub, author_full)

        assert {:ok, %{shared_secret: ^expected}} =
                 Kem.encapsulate(author.public_key, ephemeral_private_key: eph)
      end
    end

    property "repo STAR: byte-identical serialization over random record sets" do
      record =
        gen(
          all(
            collection <- nsid(),
            rkey <- string(:alphanumeric, min_length: 1, max_length: 12),
            value <-
              map_of(string(:alphanumeric, min_length: 1, max_length: 8), json_value(1),
                max_length: 5
              )
          ) do
            {collection, rkey, value}
          end
        )

      check all(
              records <-
                uniq_list_of(record, uniq_fun: &{elem(&1, 0), elem(&1, 1)}, max_length: 12),
              data <- binary(length: 32)
            ) do
        commit = %{
          "ver" => 1,
          "repo" => "did:plc:author",
          "space" => "at://did:plc:a/space/com.example.group/default",
          "rev" => "3kbcq3p7ad2c2",
          "data" => data
        }

        assert SpecEncoder.serialize_repo(commit, records) == Repo.serialize(commit, records)
      end
    end

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
