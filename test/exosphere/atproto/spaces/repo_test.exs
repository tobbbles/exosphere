defmodule Exosphere.ATProto.Spaces.RepoTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CID, Star}
  alias Exosphere.ATProto.CBOR, as: DagCbor
  alias Exosphere.ATProto.Spaces.{Commit, Lthash, Repo}

  @space "at://did:example:space/space/app.bsky.group/test"
  @repo "did:example:alice"
  @ctx %{space: @space, repo: @repo}
  @secret :binary.copy(<<9>>, 32)

  # Deliberately not in path order: serialization sorts by key bytes.
  @records [
    {"com.example.thread", "3jzfcgty2a2h", %{"$type" => "com.example.thread", "text" => "hi"}},
    {"z.foo.bar", "a", %{"$type" => "z.foo.bar", "n" => 1}},
    {"a.foo.bar", "abcdefgh", %{"$type" => "a.foo.bar", "ok" => true}}
  ]

  setup do
    commit = commit_for(@records)
    star = Repo.serialize(commit, @records)
    %{commit: commit, star: star, mac: Commit.mac(commit, @secret)}
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

  test "verify/4 authenticates the commit and every record", %{star: star, mac: mac} do
    assert {:ok, verified} = Repo.verify(star, @ctx, @secret, mac)
    assert verified.rev == "3kbcq3p7ad2c2"
    assert length(verified.records) == 3
    assert Commit.matches?(verified.lthash, verified.commit)

    assert %{collection: "z.foo.bar", rkey: "a", record: %{"n" => 1}, cid: %CID{}} =
             List.last(verified.records)
  end

  test "an empty repo is valid and has no pairs" do
    commit = commit_for([])
    star = Repo.serialize(commit, [])
    assert {:ok, %{pairs: []}} = Star.decode(star)
    assert {:ok, %{records: []}} = Repo.verify(star, @ctx, @secret, Commit.mac(commit, @secret))
  end

  test "the MAC, the requested repo and space all bind", %{star: star, mac: mac} do
    assert {:error, :invalid_mac} = Repo.verify(star, @ctx, :binary.copy(<<1>>, 32), mac)
    assert {:error, :repo_mismatch} = Repo.verify(star, %{@ctx | repo: "did:x:y"}, @secret, mac)

    assert {:error, :space_mismatch} =
             Repo.verify(star, %{@ctx | space: @space <> "2"}, @secret, mac)
  end

  test "a record the commit does not cover fails the digest", %{commit: commit, mac: mac} do
    extra = [{"c.d.e", "x", %{"sneaky" => true}} | @records]
    star = Repo.serialize(commit, extra)
    assert {:error, :records_do_not_match_commit} = Repo.verify(star, @ctx, @secret, mac)

    tampered = [{"z.foo.bar", "a", %{"$type" => "z.foo.bar", "n" => 2}} | tl(tl(@records))]
    star = Repo.serialize(commit, [hd(@records) | tampered])
    assert {:error, :records_do_not_match_commit} = Repo.verify(star, @ctx, @secret, mac)
  end

  test "out-of-order or duplicate keys reject the archive", %{commit: commit, mac: mac} do
    meta = Map.put(Commit.to_dag_cbor(commit), "$type", "atproto-space-repo")
    pairs = Enum.map(@records, fn {c, r, rec} -> {c <> "/" <> r, DagCbor.encode!(rec)} end)

    assert {:error, {:records_out_of_order, _}} =
             Repo.verify(Star.encode(meta, pairs), @ctx, @secret, mac)

    sorted = Enum.sort(pairs)
    dup = [hd(sorted) | sorted]

    assert {:error, {:records_out_of_order, _}} =
             Repo.verify(Star.encode(meta, dup), @ctx, @secret, mac)

    assert_raise ArgumentError, fn -> Repo.serialize(commit, [hd(@records) | @records]) end
  end

  test "invalid paths, non-map records, and wrong profiles are refused", %{
    commit: commit,
    mac: mac
  } do
    meta = Map.put(Commit.to_dag_cbor(commit), "$type", "atproto-space-repo")

    assert {:error, {:invalid_record_path, "not-a-path"}} =
             Repo.verify(
               Star.encode(meta, [{"not-a-path", DagCbor.encode!(%{})}]),
               @ctx,
               @secret,
               mac
             )

    assert {:error, :invalid_record} =
             Repo.verify(
               Star.encode(meta, [{"a.b.c/x", DagCbor.encode!([1])}]),
               @ctx,
               @secret,
               mac
             )

    assert {:error, :invalid_record} =
             Repo.verify(
               Star.encode(meta, [{"a.b.c/x", DagCbor.encode!(%{}) <> <<0>>}]),
               @ctx,
               @secret,
               mac
             )

    other = Map.put(meta, "$type", "atproto-space-meta")
    assert {:error, :wrong_star_type} = Repo.verify(Star.encode(other, []), @ctx, @secret, mac)

    v2 = Map.put(meta, "ver", 2)

    assert {:error, {:unsupported_commit_version, 2}} =
             Repo.verify(Star.encode(v2, []), @ctx, @secret, mac)
  end

  test "values over the profile's 1 MiB limit are refused before reading", %{
    commit: commit,
    mac: mac
  } do
    meta = Map.put(Commit.to_dag_cbor(commit), "$type", "atproto-space-repo")
    big = Star.encode(meta, [{"a.b.c/x", :binary.copy(<<0>>, 1024 * 1024 + 1)}])
    assert {:error, {:length_exceeds_limit, :value}} = Repo.verify(big, @ctx, @secret, mac)
  end

  test "read/1 checks the records without a MAC (importRepo)", %{star: star} do
    assert {:ok, %{records: records}} = Repo.read(star)
    assert length(records) == 3
  end
end
