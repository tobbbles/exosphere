defmodule Exosphere.ATProto.Spaces.RepoTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.CBOR, as: DagCbor
  alias Exosphere.ATProto.{CID, Crypto, Star}
  alias Exosphere.ATProto.Spaces.{Commit, Kem, Lthash, Mac, Repo}

  @space "at://did:example:space/space/app.bsky.group/test"
  @repo "did:example:alice"
  @ctx %{space: @space, repo: @repo}

  # Deliberately not in path order: serialization sorts by key bytes.
  @records [
    {"com.example.thread", "3jzfcgty2a2h", %{"$type" => "com.example.thread", "text" => "hi"}},
    {"z.foo.bar", "a", %{"$type" => "z.foo.bar", "n" => 1}},
    {"a.foo.bar", "abcdefgh", %{"$type" => "a.foo.bar", "ok" => true}}
  ]

  setup do
    commit = commit_for(@records)
    star = Repo.serialize(commit, @records)

    # One getRepo exchange: the syncer's encapsulation, and the MAC headers the
    # host answers with after decapsulating the Accept-Signature key share.
    {:ok, author_kem} = Crypto.generate_keypair(:p256)
    {:ok, kem} = Kem.encapsulate(author_kem.public_key)
    {:ok, request} = Mac.parse_request(Mac.format_request(:commit, kem.key_share), :commit)
    {:ok, params} = Mac.decapsulate(request, author_kem.private_key)

    %{
      commit: commit,
      star: star,
      kem: kem,
      params: params,
      mac: Commit.mac_headers(commit, params)
    }
  end

  defp commit_for(records) do
    hash =
      Enum.reduce(records, Lthash.new(), fn {c, r, record}, h ->
        Commit.add_record(h, c, r, CID.encode(CID.create!(record)))
      end)

    Commit.build(hash, %{space: @space, repo: @repo, rev: "3kbcq3p7ad2c2"})
  end

  test "serialize/2 writes the atproto-space-repo profile in strict key order", %{
    commit: commit,
    star: star
  } do
    assert {:ok, %{meta: meta, pairs: pairs}} = Star.decode(star)

    assert meta == Map.put(commit, "$type", "atproto-space-repo")

    assert Enum.map(pairs, &elem(&1, 0)) ==
             ["a.foo.bar/abcdefgh", "com.example.thread/3jzfcgty2a2h", "z.foo.bar/a"]

    assert {_, value} = List.keyfind(pairs, "z.foo.bar/a", 0)
    assert value == DagCbor.encode!(%{"$type" => "z.foo.bar", "n" => 1})
  end

  test "verify/4 authenticates the commit and every record", %{star: star, kem: kem, mac: mac} do
    assert {:ok, verified} = Repo.verify(star, @ctx, kem, mac)
    assert verified.rev == "3kbcq3p7ad2c2"
    assert length(verified.records) == 3
    assert Commit.matches?(verified.lthash, verified.commit)

    assert %{collection: "z.foo.bar", rkey: "a", record: %{"n" => 1}, cid: %CID{}} =
             List.last(verified.records)
  end

  test "an empty repo is valid and has no pairs", %{kem: kem, params: params} do
    commit = commit_for([])
    star = Repo.serialize(commit, [])
    assert {:ok, %{pairs: []}} = Star.decode(star)

    assert {:ok, %{records: []}} =
             Repo.verify(star, @ctx, kem, Commit.mac_headers(commit, params))
  end

  test "the MAC, the requested repo and space all bind", %{star: star, kem: kem, mac: mac} do
    other_secret = %{kem | shared_secret: :binary.copy(<<1>>, 32)}

    assert {:error, {:invalid_space_mac, :mac_mismatch}} =
             Repo.verify(star, @ctx, other_secret, mac)

    assert {:error, :repo_mismatch} = Repo.verify(star, %{@ctx | repo: "did:x:y"}, kem, mac)

    assert {:error, :space_mismatch} =
             Repo.verify(star, %{@ctx | space: @space <> "2"}, kem, mac)

    # No MAC headers at all.
    assert {:error, {:invalid_space_mac, _}} = Repo.verify(star, @ctx, kem, [])
  end

  test "an archive whose commit is not the MAC'd one fails", %{kem: kem, mac: mac} do
    # A valid archive for other contents, served with the first commit's MAC.
    records = [{"a.foo.bar", "x", %{"$type" => "a.foo.bar"}}]
    star = Repo.serialize(commit_for(records), records)

    assert {:error, {:invalid_space_mac, :commit_mismatch}} = Repo.verify(star, @ctx, kem, mac)
  end

  test "a record the commit does not cover fails the digest", %{
    commit: commit,
    kem: kem,
    mac: mac
  } do
    extra = [{"c.d.e", "x", %{"sneaky" => true}} | @records]
    star = Repo.serialize(commit, extra)
    assert {:error, :records_do_not_match_commit} = Repo.verify(star, @ctx, kem, mac)

    [first, _second | rest] = @records
    tampered = [{"z.foo.bar", "a", %{"$type" => "z.foo.bar", "n" => 2}} | rest]
    star = Repo.serialize(commit, [first | tampered])
    assert {:error, :records_do_not_match_commit} = Repo.verify(star, @ctx, kem, mac)
  end

  test "out-of-order or duplicate keys reject the archive", %{
    commit: commit,
    kem: kem,
    mac: mac
  } do
    meta = Map.put(Commit.to_dag_cbor(commit), "$type", "atproto-space-repo")
    pairs = Enum.map(@records, fn {c, r, rec} -> {c <> "/" <> r, DagCbor.encode!(rec)} end)

    assert {:error, {:records_out_of_order, _}} =
             Repo.verify(Star.encode(meta, pairs), @ctx, kem, mac)

    sorted = Enum.sort(pairs)
    dup = [hd(sorted) | sorted]

    assert {:error, {:records_out_of_order, _}} =
             Repo.verify(Star.encode(meta, dup), @ctx, kem, mac)

    assert_raise ArgumentError, fn -> Repo.serialize(commit, [hd(@records) | @records]) end
  end

  test "invalid paths, non-map records, and wrong profiles are refused", %{
    commit: commit,
    kem: kem,
    mac: mac
  } do
    meta = Map.put(Commit.to_dag_cbor(commit), "$type", "atproto-space-repo")

    assert {:error, {:invalid_record_path, "not-a-path"}} =
             Repo.verify(
               Star.encode(meta, [{"not-a-path", DagCbor.encode!(%{})}]),
               @ctx,
               kem,
               mac
             )

    assert {:error, :invalid_record} =
             Repo.verify(Star.encode(meta, [{"a.b.c/x", DagCbor.encode!([1])}]), @ctx, kem, mac)

    assert {:error, :invalid_record} =
             Repo.verify(
               Star.encode(meta, [{"a.b.c/x", DagCbor.encode!(%{}) <> <<0>>}]),
               @ctx,
               kem,
               mac
             )

    other = Map.put(meta, "$type", "atproto-space-meta")
    assert {:error, :wrong_star_type} = Repo.verify(Star.encode(other, []), @ctx, kem, mac)

    v2 = Map.put(meta, "ver", 2)

    assert {:error, {:unsupported_commit_version, 2}} =
             Repo.verify(Star.encode(v2, []), @ctx, kem, mac)
  end

  test "values over the profile's 1 MiB limit are refused before reading", %{
    commit: commit,
    kem: kem,
    mac: mac
  } do
    meta = Map.put(Commit.to_dag_cbor(commit), "$type", "atproto-space-repo")
    big = Star.encode(meta, [{"a.b.c/x", :binary.copy(<<0>>, 1024 * 1024 + 1)}])
    assert {:error, {:length_exceeds_limit, :value}} = Repo.verify(big, @ctx, kem, mac)
  end

  test "read/1 checks the records without a MAC (importRepo)", %{star: star} do
    assert {:ok, %{records: records}} = Repo.read(star)
    assert length(records) == 3
  end

  test "byte strings survive export -> import -> re-export with the same CID" do
    link = CID.create!(%{"x" => 1})
    raw = <<0, 159, 146, 150, 255>>

    record = %{
      "$type" => "com.example.blob",
      "raw" => %CBOR.Tag{tag: :bytes, value: raw},
      "nested" => [%{"b" => %CBOR.Tag{tag: :bytes, value: "text-looking bytes"}}],
      "ref" => link
    }

    records = [{"com.example.blob", "self", record}]
    star = Repo.serialize(commit_for(records), records)

    assert {:ok, %{records: [imported], commit: commit}} = Repo.read(star)

    # Bytes stay bytes, links become CIDs.
    assert imported.record["raw"] == %CBOR.Tag{tag: :bytes, value: raw}
    assert [%{"b" => %CBOR.Tag{tag: :bytes}}] = imported.record["nested"]
    assert imported.record["ref"] == link

    # The re-encoding is the archived block, so the CID is unchanged ...
    assert DagCbor.encode!(imported.record) == DagCbor.encode!(record)
    assert CID.encode(CID.create!(imported.record)) == CID.encode(imported.cid)

    # ... and a re-export of the imported repo verifies against the same commit.
    reexported =
      Repo.serialize(commit, [{imported.collection, imported.rkey, imported.record}])

    assert {:ok, %{records: [again]}} = Repo.read(reexported)
    assert again.cid == imported.cid
  end
end
