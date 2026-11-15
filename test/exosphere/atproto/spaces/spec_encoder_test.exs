defmodule Exosphere.ATProto.Spaces.SpecEncoderTest do
  @moduledoc """
  The G6 differential: the spec-only second encoder (`SpecEncoder`, written
  from the proposal and the RFCs it defers to) against both the production
  implementation (`Spaces.{Lthash,Kem,Mac,Repo}`), the reference corpus, and
  the published test vectors.

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

  # The CFRG HPKE test vector for exactly the MAC suite: mode 0, kem_id 16
  # (DHKEM(P-256, HKDF-SHA256)), kdf_id 1, aead_id 65535 (Export-only), from
  # test-vectors.json in github.com/cfrg/draft-irtf-cfrg-hpke.
  @cfrg %{
    info: "4f6465206f6e2061204772656369616e2055726e",
    sk_rm: "62c3868357a464f8461d03aa0182c7cebcde841036aea7230ddc7339f1088346",
    pk_rm:
      "046c6bb9e1976402c692fef72552f4aaeedd83a5e5079de3d7ae732da0f397b15921fb9c52c9866affc8e29c0271a35937023a9245982ec18bab1eb157cf16fc33",
    enc:
      "04d804370b7e24b94749eb1dc8df6d4d4a5d75f9effad01739ebcad5c54a40d57aaa8b4190fc124dbde2e4f1e1d1b012a3bc4038157dc29b55533a932306d8d38d",
    exports: [
      {"", 32, "8cf837d5bf1994f0fac3ee1faa671d07e9a38b7f6153bdbb8a66b90159ef7d13"},
      {"00", 32, "3c7708f8ae1f510f4439fa514deb1c7ece7a29085a2e8270a84b6ad6481cc0b4"},
      {"54657374436f6e74657874", 32,
       "f53fb127f67dabf35b14fae14b53e6ce5c49e572f95eb4ef7a3b3cb9cd85f12b"}
    ]
  }

  # atproto's vector (packages/space/tests/kem.test.ts @ d4def6e): the CFRG
  # keys with info "atproto-mac" and an empty exporter context, computed with
  # Go's crypto/hpke.
  @atproto_mac_secret "2060e0558d1b34c10086bc137f849bb79ba59fcdc30544418e35c9cd301f0d0d"

  @space "at://did:example:space/space/app.bsky.group/test"
  @key_share "did:key:zDnaExample"

  describe "the spec encoder independently reproduces the corpus and the vectors" do
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

    test "every HPKE export of the CFRG vector, from its own key schedule over :crypto's ECDH" do
      dh = SpecEncoder.ecdh(unhex(@cfrg.sk_rm), unhex(@cfrg.enc))

      for {context, length, expected} <- @cfrg.exports do
        assert SpecEncoder.export_secret(
                 dh,
                 unhex(@cfrg.enc),
                 unhex(@cfrg.pk_rm),
                 unhex(@cfrg.info),
                 unhex(context),
                 length
               ) == unhex(expected)
      end
    end

    test "atproto's MAC secret vector" do
      dh = SpecEncoder.ecdh(unhex(@cfrg.sk_rm), unhex(@cfrg.enc))

      assert SpecEncoder.mac_secret(dh, unhex(@cfrg.enc), unhex(@cfrg.pk_rm)) ==
               unhex(@atproto_mac_secret)
    end

    test "the reference's MAC request and commit headers (mac.test.ts @ d4def6e)" do
      # The exact strings the reference's own tests pin.
      assert SpecEncoder.accept_signature("mac", "atproto-space-commit", @key_share) ==
               ~s|mac=("atproto-space-commit";sf);keyid="did:key:zDnaExample";tag="atproto-space-commit"|

      assert SpecEncoder.accept_signature("mac", "atproto-space-record", @key_share) ==
               ~s|mac=("atproto-space-record";sf);keyid="did:key:zDnaExample";tag="atproto-space-record"|

      covered =
        SpecEncoder.commit_header(
          1,
          "did:example:alice",
          @space,
          "3kbcq3p7ad400",
          :binary.copy(<<1>>, 32)
        )

      assert covered ==
               ~s|ver=1, repo="did:example:alice", space="#{@space}", rev="3kbcq3p7ad400", data=:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:|

      params = SpecEncoder.signature_params("atproto-space-commit", @key_share)

      assert SpecEncoder.signature_base("atproto-space-commit", covered, params) ==
               ~s|"atproto-space-commit";sf: #{covered}\n"@signature-params": #{params}|

      uri = @space <> "/did:example:alice/app.bsky.feed.post/1"
      cid = "bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244"
      assert SpecEncoder.record_header(uri, cid) == ~s|uri="#{uri}", cid="#{cid}"|
    end

    test "every record value's CID, as folded into the set hash" do
      for variant <- @commit_mac["records"] do
        assert SpecEncoder.record_cid_bytes(variant["value"]) == unhex(variant["cidBytes"])
        assert SpecEncoder.record_cid_string(variant["value"]) == variant["cid"]
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
    property "KEM: the spec's HPKE export agrees with Kem.encapsulate/2 and decapsulate/2" do
      check all(seed <- binary(length: 32)) do
        {:ok, author} = Crypto.generate_keypair(:p256)
        {:ok, author_full} = Crypto.decompress(author.public_key, :p256)
        eph = :crypto.hash(:sha256, seed)
        {eph_pub, _} = :crypto.generate_key(:ecdh, :secp256r1, eph)

        expected =
          SpecEncoder.mac_secret(SpecEncoder.ecdh(eph, author_full), eph_pub, author_full)

        assert {:ok, %{key_share: key_share, shared_secret: ^expected}} =
                 Kem.encapsulate(author.public_key, ephemeral_private_key: eph)

        assert {:ok, ^expected} = Kem.decapsulate(author.private_key, key_share)
      end
    end

    property "commit MAC: the host's headers are byte-identical, and the spec's MAC verifies" do
      check all(
              space <- string(32..126, min_length: 1, max_length: 600),
              repo <- string(:alphanumeric, min_length: 1, max_length: 64),
              rev <- string(:alphanumeric, length: 13),
              data <- binary(length: 32),
              secret <- binary(length: 32),
              label <- string(?a..?z, min_length: 1, max_length: 8)
            ) do
        commit = %{"ver" => 1, "space" => space, "repo" => repo, "rev" => rev, "data" => data}
        params = SpecEncoder.signature_params("atproto-space-commit", @key_share)
        covered = SpecEncoder.commit_header(1, repo, space, rev, data)

        mac =
          SpecEncoder.mac(
            secret,
            SpecEncoder.signature_base("atproto-space-commit", covered, params)
          )

        spec_headers = [
          {"atproto-space-commit", covered},
          {"signature-input", label <> "=" <> params},
          {"signature", SpecEncoder.signature(label, mac)}
        ]

        {:ok, request} =
          Mac.parse_request(
            SpecEncoder.accept_signature(label, "atproto-space-commit", @key_share),
            :commit
          )

        assert Mac.commit_headers(commit, Map.put(request, :shared_secret, secret)) ==
                 spec_headers

        assert :ok =
                 Mac.verify_commit(
                   commit,
                   %{key_share: @key_share, shared_secret: secret},
                   spec_headers
                 )
      end
    end

    property "record MAC: byte-identical over arbitrary URIs and values" do
      check all(
              uri <- string(32..126, min_length: 1, max_length: 300),
              value <- map_of(string(:alphanumeric, min_length: 1, max_length: 8), json_value(1)),
              secret <- binary(length: 32)
            ) do
        cid = CID.create!(value)
        assert SpecEncoder.record_cid_bytes(value) == CID.to_bytes(cid)
        cid_string = SpecEncoder.record_cid_string(value)

        params = SpecEncoder.signature_params("atproto-space-record", @key_share)
        covered = SpecEncoder.record_header(uri, cid_string)

        mac =
          SpecEncoder.mac(
            secret,
            SpecEncoder.signature_base("atproto-space-record", covered, params)
          )

        {:ok, request} =
          Mac.parse_request(
            SpecEncoder.accept_signature("mac", "atproto-space-record", @key_share),
            :record
          )

        assert Mac.record_headers(uri, cid, Map.put(request, :shared_secret, secret)) == [
                 {"atproto-space-record", covered},
                 {"signature-input", "mac=" <> params},
                 {"signature", SpecEncoder.signature("mac", mac)}
               ]
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
