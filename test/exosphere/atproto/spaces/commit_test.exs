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
  @rev "3kbcq3p7ad422"
  @ctx %{space: @space, repo: @repo, rev: @rev}

  setup do
    # The syncer/host handshake: a fresh HPKE secret against the author's KEM
    # key, requested in Accept-Signature and decapsulated on the host side.
    {:ok, author_kem} = Crypto.generate_keypair(:p256)
    {:ok, kem} = Kem.encapsulate(author_kem.public_key)
    {:ok, request} = Mac.parse_request(Mac.format_request(:commit, kem.key_share), :commit)
    {:ok, params} = Mac.decapsulate(request, author_kem.private_key)
    %{kem: kem, params: params}
  end

  test "build/2 produces a defs#commit over the set hash" do
    hash = repo([{"c.a", "1", @cid_a}])
    commit = Commit.build(hash, @ctx)

    assert commit == %{
             "ver" => 1,
             "repo" => @repo,
             "space" => @space,
             "rev" => @rev,
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

  test "verify/4 accepts the host's MAC headers under the request's secret", %{
    kem: kem,
    params: params
  } do
    commit = Commit.build(repo([{"c.a", "1", @cid_a}]), @ctx)
    headers = Commit.mac_headers(commit, params)

    # The covered header and the signature under the requested label.
    assert headers == Mac.commit_headers(commit, params)
    assert {"signature-input", "mac=" <> _} = List.keyfind(headers, "signature-input", 0)

    assert {"atproto-space-commit", "ver=1, repo=" <> _} =
             List.keyfind(headers, "atproto-space-commit", 0)

    assert :ok = Commit.verify(commit, %{space: @space, repo: @repo}, kem, headers)
  end

  test "verify/4 binds the requested repo and space, and the secret", %{kem: kem, params: params} do
    commit = Commit.build(repo([{"c.a", "1", @cid_a}]), @ctx)
    headers = Commit.mac_headers(commit, params)

    assert {:error, :repo_mismatch} =
             Commit.verify(commit, %{space: @space, repo: "did:example:bob"}, kem, headers)

    assert {:error, :space_mismatch} =
             Commit.verify(commit, %{space: @space <> "x", repo: @repo}, kem, headers)

    other = %{kem | shared_secret: :binary.copy(<<1>>, 32)}

    assert {:error, {:invalid_space_mac, :mac_mismatch}} =
             Commit.verify(commit, %{space: @space, repo: @repo}, other, headers)

    # No MAC at all is a MAC failure too.
    assert {:error, {:invalid_space_mac, :missing_http_signature}} =
             Commit.verify(commit, %{space: @space, repo: @repo}, kem, [])
  end

  test "a commit that differs from the MAC'd header fails", %{kem: kem, params: params} do
    commit = Commit.build(repo([{"c.a", "1", @cid_a}]), @ctx)
    headers = Commit.mac_headers(commit, params)
    ctx = %{space: @space, repo: @repo}

    assert {:error, {:invalid_space_mac, :commit_mismatch}} =
             Commit.verify(%{commit | "data" => :crypto.hash(:sha256, "x")}, ctx, kem, headers)

    assert {:error, {:invalid_space_mac, :commit_mismatch}} =
             Commit.verify(%{commit | "rev" => "3kbcq3p7ad423"}, ctx, kem, headers)
  end

  test "unknown versions and malformed commits are invalid", %{kem: kem, params: params} do
    commit = Commit.build(Lthash.new(), @ctx)
    headers = Commit.mac_headers(commit, params)
    ctx = %{space: @space, repo: @repo}

    assert {:error, :invalid_commit} = Commit.verify(%{commit | "ver" => 2}, ctx, kem, headers)

    assert {:error, :invalid_commit} =
             Commit.verify(%{commit | "data" => <<1, 2>>}, ctx, kem, headers)

    assert {:error, :invalid_commit} = Commit.verify(Map.delete(commit, "rev"), ctx, kem, headers)

    # defs#commit: rev is format tid, repo a did, space a space-ref.
    for bad <- [
          %{commit | "rev" => "not-a-tid"},
          %{commit | "rev" => "3KBCQ3P7AD400"},
          %{commit | "repo" => "alice"},
          %{commit | "space" => "at://did:example:space/app.bsky.group/test"}
        ] do
      refute Commit.well_formed?(bad)
    end

    assert {:error, :invalid_commit} =
             Commit.verify(%{commit | "rev" => "not-a-tid"}, ctx, kem, headers)
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
