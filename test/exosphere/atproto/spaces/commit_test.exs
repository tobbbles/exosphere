defmodule Exosphere.ATProto.Spaces.CommitTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.Spaces.Commit
  alias Exosphere.ATProto.Spaces.Lthash

  # cids of `{text: 'hello'}` and `{text: 'world'}` (from the reference test suite)
  @cid_a "bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244"
  @cid_b "bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a"

  @ctx %{
    space: "at://did:example:space/space/app.bsky.group/test",
    author: "did:example:alice",
    rev: "3kbcq3p7ad400"
  }

  setup do
    {:ok, keypair} = Crypto.generate_keypair(:secp256k1)
    %{keypair: keypair}
  end

  test "encode_ctx/2 is length-prefixed and domain-separated" do
    ikm = :binary.copy(<<7>>, 32)
    encoded = Commit.encode_ctx(@ctx, ikm)

    assert binary_part(encoded, 0, 16) == "atproto-space-v1"

    <<len::big-16>> = binary_part(encoded, 16, 2)
    assert len == byte_size(@ctx.space)

    # Unambiguous across field boundaries: without prefixes these collide.
    a = Commit.encode_ctx(%{space: "ab", author: "c", rev: "d"}, ikm)
    b = Commit.encode_ctx(%{space: "a", author: "bc", rev: "d"}, ikm)
    assert a != b

    assert_raise ArgumentError, fn ->
      Commit.encode_ctx(%{@ctx | space: String.duplicate("s", 0x10000)}, ikm)
    end
  end

  test "sign/4 produces a well-formed commit", %{keypair: keypair} do
    repo = repo([{"c.a", "1", @cid_a}])
    {:ok, commit} = Commit.sign(repo, @ctx, keypair.private_key, :secp256k1)

    assert commit["ver"] == 1
    assert commit["rev"] == @ctx.rev
    assert commit["hash"] == Lthash.digest(repo)
    assert byte_size(commit["hash"]) == 32
    assert byte_size(commit["ikm"]) == 32
    assert byte_size(commit["mac"]) == 32
    assert byte_size(commit["sig"]) > 0
  end

  test "verify/4 accepts its own commit and the contents match", %{keypair: keypair} do
    repo = repo([{"c.a", "1", @cid_a}])
    {:ok, commit} = Commit.sign(repo, @ctx, keypair.private_key, :secp256k1)

    assert :ok = Commit.verify(commit, @ctx, keypair.public_key, :secp256k1)
    assert Lthash.digest(repo) == commit["hash"]
  end

  test "each sign gets a fresh ikm, mac, and sig — for deniability", %{keypair: keypair} do
    repo = repo([{"c.a", "1", @cid_a}])

    {:ok, a} = Commit.sign(repo, @ctx, keypair.private_key, :secp256k1)
    {:ok, b} = Commit.sign(repo, @ctx, keypair.private_key, :secp256k1)

    assert a["ikm"] != b["ikm"]
    assert a["mac"] != b["mac"]
    assert a["sig"] != b["sig"]
    assert a["hash"] == b["hash"]
  end

  test "rejects a signature from a different key", %{keypair: keypair} do
    {:ok, other} = Crypto.generate_keypair(:secp256k1)
    repo = repo([{"c.a", "1", @cid_a}])
    {:ok, commit} = Commit.sign(repo, @ctx, keypair.private_key, :secp256k1)

    assert {:error, :invalid_signature} =
             Commit.verify(commit, @ctx, other.public_key, :secp256k1)
  end

  test "does not verify under a changed space, author, or rev", %{keypair: keypair} do
    repo = repo([{"c.a", "1", @cid_a}])
    {:ok, commit} = Commit.sign(repo, @ctx, keypair.private_key, :secp256k1)

    for ctx <- [
          %{@ctx | space: "at://did:example:space/space/app.bsky.group/other"},
          %{@ctx | author: "did:example:bob"},
          %{@ctx | rev: "3kbcq3p7ad999"}
        ] do
      assert {:error, _} = Commit.verify(commit, ctx, keypair.public_key, :secp256k1)
    end
  end

  test "a tampered hash fails the MAC, not the signature", %{keypair: keypair} do
    repo = repo([{"c.a", "1", @cid_a}])
    {:ok, commit} = Commit.sign(repo, @ctx, keypair.private_key, :secp256k1)

    tampered = %{commit | "hash" => Lthash.digest(Lthash.new())}

    # The signature still covers only the ctx — the MAC is what catches this,
    # and what a leaked commit cannot prove about contents.
    assert {:error, :invalid_mac} = Commit.verify(tampered, @ctx, keypair.public_key, :secp256k1)
  end

  test "rejects a rev that disagrees with the ctx and unknown versions", %{keypair: keypair} do
    repo = repo([{"c.a", "1", @cid_a}])
    {:ok, commit} = Commit.sign(repo, @ctx, keypair.private_key, :secp256k1)

    assert {:error, :rev_mismatch} =
             Commit.verify(
               %{commit | "rev" => "3kbcq3p7ad999"},
               @ctx,
               keypair.public_key,
               :secp256k1
             )

    assert {:error, :invalid_commit} =
             Commit.verify(%{commit | "ver" => 2}, @ctx, keypair.public_key, :secp256k1)
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

  test "p256 keys verify too" do
    {:ok, keypair} = Crypto.generate_keypair(:p256)
    repo = repo([{"c.a", "1", @cid_a}])
    {:ok, commit} = Commit.sign(repo, @ctx, keypair.private_key, :p256)
    assert :ok = Commit.verify(commit, @ctx, keypair.public_key, :p256)
  end

  defp repo(records) do
    Enum.reduce(records, Lthash.new(), fn {c, r, cid}, h ->
      Commit.add_record(h, c, r, cid)
    end)
  end

  defp first_slash(s), do: s |> String.split("/") |> hd() |> byte_size()
end
