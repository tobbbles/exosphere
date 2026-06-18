defmodule Exosphere.ATProto.Repo.CommitTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CBOR, CID, Crypto, TID}
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
