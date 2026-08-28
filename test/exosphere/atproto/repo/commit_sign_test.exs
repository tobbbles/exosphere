defmodule Exosphere.ATProto.Repo.CommitSignTest do
  use ExUnit.Case, async: true

  # Aliased under a distinct name so `%CBOR.Tag{}` still refers to the `:cbor`
  # library struct.
  alias Exosphere.ATProto.CBOR, as: DagCBOR
  alias Exosphere.ATProto.{CID, Crypto}
  alias Exosphere.ATProto.Repo.Commit

  @did "did:plc:44ybard66vv44zksje25o7dz"
  @rev "3lbqmqtqhpk2a"

  defp root, do: CID.create!(%{"l" => nil, "e" => []})

  for curve <- [:secp256k1, :p256] do
    describe "sign/3 on #{curve}" do
      @describetag curve: curve

      setup %{curve: curve} do
        {:ok, keypair} = Crypto.generate_keypair(curve)
        {:ok, keypair: keypair, curve: curve}
      end

      test "produces a commit its own verifier accepts", %{keypair: kp, curve: curve} do
        commit = Commit.build(@did, root(), @rev)

        assert {:ok, signed} = Commit.sign(commit, kp.private_key, curve)
        assert :ok = Commit.verify(signed, kp.public_key, curve)
      end

      test "the signature does not survive tampering", %{keypair: kp, curve: curve} do
        signed = Commit.sign!(Commit.build(@did, root(), @rev), kp.private_key, curve)

        tampered = Map.put(signed, "rev", "3lbqmqtqhpk2b")
        assert {:error, :invalid_signature} = Commit.verify(tampered, kp.public_key, curve)
      end

      test "re-signing replaces the old signature", %{keypair: kp, curve: curve} do
        signed = Commit.sign!(Commit.build(@did, root(), @rev), kp.private_key, curve)
        again = Commit.sign!(signed, kp.private_key, curve)

        assert :ok = Commit.verify(again, kp.public_key, curve)
        # The signed payload is the commit minus `sig`, so both cover the same
        # bytes and the CID of the unsigned form is unchanged.
        assert Map.delete(again, "sig") == Map.delete(signed, "sig")
      end
    end
  end

  describe "build/1" do
    test "sets the current commit version and a null prev" do
      commit = Commit.build(@did, root(), @rev)

      assert commit["did"] == @did
      assert commit["version"] == 3
      assert commit["rev"] == @rev
      assert commit["prev"] == nil
      assert commit["data"] == root()
    end

    test "takes an explicit prev" do
      previous = CID.create!(%{"old" => true})
      commit = Commit.build(@did, root(), @rev, prev: previous)

      assert commit["prev"] == previous
    end
  end

  describe "the encoded block" do
    setup do
      {:ok, keypair} = Crypto.generate_keypair(:secp256k1)
      {:ok, keypair: keypair}
    end

    test "carries `sig` as a CBOR byte string, not text", %{keypair: kp} do
      signed = Commit.sign!(Commit.build(@did, root(), @rev), kp.private_key, :secp256k1)

      assert %CBOR.Tag{tag: :bytes} = signed["sig"]

      # Major type 2 on the wire. Encoding a raw binary here would make it a
      # text string, changing the block's CID and breaking every consumer.
      bytes = DagCBOR.encode!(signed)
      assert {:ok, decoded} = DagCBOR.decode(bytes)
      assert is_binary(decoded["sig"])
      assert byte_size(decoded["sig"]) == 64
    end

    test "the CID is stable across encode/decode of the bytes", %{keypair: kp} do
      signed = Commit.sign!(Commit.build(@did, root(), @rev), kp.private_key, :secp256k1)

      bytes = DagCBOR.encode!(signed)
      cid = CID.create!(signed)

      assert :crypto.hash(:sha256, bytes) == cid.hash
    end

    test "a decoded commit still verifies", %{keypair: kp} do
      signed = Commit.sign!(Commit.build(@did, root(), @rev), kp.private_key, :secp256k1)

      {:ok, decoded} = DagCBOR.decode(DagCBOR.encode!(signed))

      # Verification strips `sig` before re-encoding, so the bytes-to-text
      # asymmetry documented on the module does not reach it.
      assert :ok = Commit.verify(decoded, kp.public_key, :secp256k1)
    end
  end
end
