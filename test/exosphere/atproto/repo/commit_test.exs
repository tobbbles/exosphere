defmodule Exosphere.ATProto.Repo.CommitTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CBOR, CID, Crypto, MST, TID}
  alias Exosphere.ATProto.Identity.Document
  alias Exosphere.ATProto.Repo.Commit

  defp signed_commit(curve) do
    {:ok, %{private_key: priv, public_key: pub}} = Crypto.generate_keypair(curve)

    unsigned = %{
      "did" => "did:plc:44ybard66vv44zksje25o7dz",
      "version" => 3,
      "data" => CID.create!(%{"x" => 1}),
      "rev" => TID.generate(),
      "prev" => nil
    }

    {:ok, bytes} = CBOR.encode(unsigned)
    {:ok, sig} = Crypto.sign(bytes, priv, curve)
    {Map.put(unsigned, "sig", sig), pub}
  end

  test "verify/3 accepts a correctly signed commit (secp256k1)" do
    {commit, pub} = signed_commit(:secp256k1)
    assert :ok = Commit.verify(commit, pub, :secp256k1)
  end

  test "verify/3 accepts a correctly signed commit (p256)" do
    {commit, pub} = signed_commit(:p256)
    assert :ok = Commit.verify(commit, pub, :p256)
  end

  test "verify/3 rejects a tampered commit" do
    {commit, pub} = signed_commit(:secp256k1)
    tampered = Map.put(commit, "rev", TID.generate())
    assert {:error, :invalid_signature} = Commit.verify(tampered, pub, :secp256k1)
  end

  test "verify/3 rejects a commit with a different signing key" do
    {commit, _pub} = signed_commit(:secp256k1)
    {:ok, %{public_key: other_pub}} = Crypto.generate_keypair(:secp256k1)
    assert {:error, :invalid_signature} = Commit.verify(commit, other_pub, :secp256k1)
  end

  test "verify/3 reports a missing signature" do
    {commit, pub} = signed_commit(:secp256k1)
    assert {:error, :missing_sig} = Commit.verify(Map.delete(commit, "sig"), pub, :secp256k1)
  end

  test "round-trips a commit through CBOR decode and still verifies" do
    {commit, pub} = signed_commit(:secp256k1)
    {:ok, encoded} = CBOR.encode(commit)
    {:ok, decoded} = CBOR.decode(encoded)
    assert :ok = Commit.verify(decoded, pub, :secp256k1)
  end

  describe "verify_data/2" do
    setup do
      records = %{
        "app.bsky.feed.post/3jqfcqzm3fp2j" => CID.create!(%{"text" => "one"}),
        "app.bsky.feed.post/3jqfcqzm3fr2j" => CID.create!(%{"text" => "two"})
      }

      {:ok, data_root} = MST.root_cid(records)
      %{records: records, data_root: data_root}
    end

    test "accepts a commit whose data root matches the records", ctx do
      commit = %{"did" => "did:plc:abc", "data" => ctx.data_root}
      assert :ok = Commit.verify_data(commit, ctx.records)
    end

    test "rejects a commit whose data root does not match", ctx do
      commit = %{"did" => "did:plc:abc", "data" => CID.create!(%{"other" => true})}
      assert {:error, :data_mismatch} = Commit.verify_data(commit, ctx.records)
    end

    test "reports a missing data field", ctx do
      assert {:error, :missing_data} = Commit.verify_data(%{"did" => "x"}, ctx.records)
    end
  end

  test "verify_with_document/2 extracts the signing key from a DID document" do
    {commit, pub} = signed_commit(:secp256k1)
    {:ok, multibase} = Crypto.to_multibase(pub, :secp256k1)

    {:ok, doc} =
      Document.parse(%{
        "id" => "did:plc:44ybard66vv44zksje25o7dz",
        "verificationMethod" => [
          %{
            "id" => "did:plc:44ybard66vv44zksje25o7dz#atproto",
            "type" => "Multikey",
            "controller" => "did:plc:44ybard66vv44zksje25o7dz",
            "publicKeyMultibase" => multibase
          }
        ]
      })

    assert :ok = Commit.verify_with_document(commit, doc)
  end
end
