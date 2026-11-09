defmodule Exosphere.ATProto.Spaces.CommitTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.Spaces.{Commit, Kem, Lthash, Mac}

  # cids of `{text: 'hello'}` and `{text: 'world'}` (from the reference test suite)
  @cid_a "bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244"
  @cid_b "bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a"

  @space "at://did:example:space/space/app.bsky.group/test"
  @repo "did:example:alice"
  @ctx %{space: @space, repo: @repo, rev: "3kbcq3p7ad400"}

  setup do
    # The syncer/host handshake: a fresh shared secret against the author's
    # KEM key, decapsulated on the host side.
    {:ok, author_kem} = Crypto.generate_keypair(:p256)
    {:ok, %{key_share: share, shared_secret: secret}} = Kem.encapsulate(author_kem.public_key)
    {:ok, ^secret} = Kem.decapsulate(author_kem.private_key, share)
    %{secret: secret}
  end

  test "build/2 produces a defs#commit over the set hash" do
    hash = repo([{"c.a", "1", @cid_a}])
    commit = Commit.build(hash, @ctx)

    assert commit == %{
             "ver" => 1,
             "repo" => @repo,
             "space" => @space,
             "rev" => "3kbcq3p7ad400",
             "data" => Lthash.digest(hash)
           }

    assert Commit.matches?(hash, commit)
    refute Commit.matches?(Lthash.new(), commit)
  end

  test "an empty repo's data is the documented all-zero-state digest" do
    # Proposal 0016, "Repo lifecycle": clearRecords leaves this digest.
    assert Commit.build(Lthash.new(), @ctx)["data"] ==
             Base.decode16!("e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad",
               case: :lower
             )
  end

  test "verify/4 accepts the host's MAC under the shared secret", %{secret: secret} do
    commit = Commit.build(repo([{"c.a", "1", @cid_a}]), @ctx)
    mac = Commit.mac(commit, secret)

    assert mac == Mac.commit_mac(secret, commit)
    assert :ok = Commit.verify(commit, %{space: @space, repo: @repo}, secret, mac)
  end

  test "verify/4 binds the requested repo and space, and the secret", %{secret: secret} do
    commit = Commit.build(repo([{"c.a", "1", @cid_a}]), @ctx)
    mac = Commit.mac(commit, secret)

    assert {:error, :repo_mismatch} =
             Commit.verify(commit, %{space: @space, repo: "did:example:bob"}, secret, mac)

    assert {:error, :space_mismatch} =
             Commit.verify(commit, %{space: @space <> "x", repo: @repo}, secret, mac)

    assert {:error, :invalid_mac} =
             Commit.verify(commit, %{space: @space, repo: @repo}, :binary.copy(<<1>>, 32), mac)
  end

  test "a tampered data or rev fails the MAC", %{secret: secret} do
    commit = Commit.build(repo([{"c.a", "1", @cid_a}]), @ctx)
    mac = Commit.mac(commit, secret)
    ctx = %{space: @space, repo: @repo}

    assert {:error, :invalid_mac} =
             Commit.verify(%{commit | "data" => :crypto.hash(:sha256, "x")}, ctx, secret, mac)

    assert {:error, :invalid_mac} =
             Commit.verify(%{commit | "rev" => "3kbcq3p7ad401"}, ctx, secret, mac)
  end

  test "unknown versions and malformed commits are invalid", %{secret: secret} do
    commit = Commit.build(Lthash.new(), @ctx)
    mac = Commit.mac(commit, secret)
    ctx = %{space: @space, repo: @repo}

    assert {:error, :invalid_commit} = Commit.verify(%{commit | "ver" => 2}, ctx, secret, mac)

    assert {:error, :invalid_commit} =
             Commit.verify(%{commit | "data" => <<1, 2>>}, ctx, secret, mac)

    assert {:error, :invalid_commit} = Commit.verify(Map.delete(commit, "rev"), ctx, secret, mac)
  end

  test "to_dag_cbor/1 wraps data as a byte string" do
    commit = Commit.build(Lthash.new(), @ctx)
    assert %{"data" => %CBOR.Tag{tag: :bytes}} = Commit.to_dag_cbor(commit)
  end

  test "element/3 concatenates and stays injective at the boundaries" do
    assert Commit.element("c.a", "1", @cid_a) == "c.a/1/" <> @cid_a

    # The outer fields are slash-free (NSID, base32 cid) so the first slash
    # ends the collection and the last begins the cid — even for a weird rkey.
    e1 = Commit.element("c.a", "b/1", @cid_a)
    e2 = Commit.element("c.a", "b/2", @cid_a)
    assert e1 != e2
    assert binary_part(e1, 0, first_slash(e1)) == "c.a"
  end

  describe "apply_op/2" do
    test "create, update, and delete through the oplog" do
      create = %{"collection" => "c.a", "rkey" => "1", "cid" => @cid_a, "prev" => nil}
      update = %{"collection" => "c.a", "rkey" => "1", "cid" => @cid_b, "prev" => @cid_a}
      delete = %{"collection" => "c.a", "rkey" => "1", "cid" => nil, "prev" => @cid_b}

      via_ops =
        Lthash.new()
        |> Commit.apply_op(create)
        |> Commit.apply_op(update)
        |> Commit.apply_op(delete)

      assert Lthash.empty?(via_ops)

      # An update is exactly a remove of prev plus an add of the new cid.
      assert Lthash.equal?(
               Lthash.new() |> Commit.apply_op(update),
               Lthash.new()
               |> Commit.remove_record("c.a", "1", @cid_a)
               |> Commit.add_record("c.a", "1", @cid_b)
             )
    end

    test "oplog replay converges regardless of op order" do
      ops = [
        %{"collection" => "c.a", "rkey" => "1", "cid" => @cid_a, "prev" => nil},
        %{"collection" => "c.b", "rkey" => "2", "cid" => @cid_b, "prev" => nil}
      ]

      forward = Enum.reduce(ops, Lthash.new(), &Commit.apply_op(&2, &1))
      backward = ops |> Enum.reverse() |> Enum.reduce(Lthash.new(), &Commit.apply_op(&2, &1))
      assert Lthash.equal?(forward, backward)
    end
  end

  defp repo(records) do
    Enum.reduce(records, Lthash.new(), fn {c, r, cid}, h ->
      Commit.add_record(h, c, r, cid)
    end)
  end

  defp first_slash(s), do: s |> String.split("/") |> hd() |> byte_size()
end
