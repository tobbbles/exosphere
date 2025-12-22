defmodule Exosphere.ATProto.Identity.DIDTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Identity.DID

  test "valid?/1 validates basic DID syntax" do
    assert DID.valid?("did:plc:z72i7hdynmk6r22z27h6tvur")
    assert DID.valid?("did:web:example.com")

    refute DID.valid?("not-a-did")
    refute DID.valid?("did::missing-method")
  end

  test "method/1 extracts DID method" do
    assert {:ok, :plc} = DID.method("did:plc:abc123")
    assert {:ok, :web} = DID.method("did:web:example.com")
    assert {:ok, :unknown} = DID.method("did:foo:bar")
    assert {:error, :invalid_did} = DID.method("nope")
  end
end
