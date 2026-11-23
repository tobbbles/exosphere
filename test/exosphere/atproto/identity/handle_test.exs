defmodule Exosphere.ATProto.Identity.HandleTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Identity.Handle

  test "valid?/1 enforces domain-like handle rules" do
    assert Handle.valid?("alice.example.com")
    assert Handle.valid?("a-b.example.com")

    refute Handle.valid?("nodot")
    refute Handle.valid?(".starts.with.dot")
    refute Handle.valid?("ends.with.dot.")
    refute Handle.valid?("double..dot.example.com")
    refute Handle.valid?("bad_label-.example.com")
    refute Handle.valid?("-badlabel.example.com")
  end

  test "valid?/1 rejects a TLD that starts with a digit" do
    # Per spec, the final segment (TLD) must not start with a digit.
    refute Handle.valid?("name.0")
    refute Handle.valid?("alice.123")
    refute Handle.valid?("foo.bar.123abc")
    # digits earlier in the handle remain fine
    assert Handle.valid?("0name.example.com")
    assert Handle.valid?("name.example123.com")
  end

  test "normalize/1 lowercases" do
    assert Handle.normalize("Alice.Example.COM") == "alice.example.com"
  end

  @did "did:plc:z72i7hdynmk6r22z27h6tvur"
  @other "did:plc:ewvi7nxzyoun6zhxrhs64oiz"

  describe "parse_txt_records/1 (DNS TXT at _atproto.<handle>)" do
    test "takes the single did= record, ignoring unrelated ones" do
      records = [[~c"v=spf1 -all"], [~c"did=" ++ String.to_charlist(@did)]]
      assert {:ok, @did} = Handle.parse_txt_records(records)
    end

    test "joins the character-string chunks of one record" do
      assert {:ok, @did} =
               Handle.parse_txt_records([[~c"did=did:plc:", ~c"z72i7hdynmk6r22z27h6tvur"]])
    end

    test "no did= record is :no_did_in_record" do
      assert {:error, :no_did_in_record} = Handle.parse_txt_records([[~c"hello"]])
    end

    test "several records naming different DIDs fail resolution" do
      records = [[~c"did=" ++ String.to_charlist(@did)], [~c"did=" ++ String.to_charlist(@other)]]
      assert {:error, :multiple_dids} = Handle.parse_txt_records(records)
    end

    test "a duplicated identical record is still one DID" do
      record = [~c"did=" ++ String.to_charlist(@did)]
      assert {:ok, @did} = Handle.parse_txt_records([record, record])
    end

    test "the DID must be a strictly valid atproto DID" do
      assert {:error, :invalid_did} = Handle.parse_txt_records([[~c"did=did:plc:abc"]])
      assert {:error, :invalid_did} = Handle.parse_txt_records([[~c"did=did:example:123"]])

      assert {:error, :invalid_did} =
               Handle.parse_txt_records([[~c"did=DID:PLC:Z72I7HDYNMK6R22Z27H6TVUR"]])
    end
  end

  defmodule StubHTTP do
    def get(_url, _opts), do: Process.get(:stub_response)
  end

  describe "resolve_https/2" do
    test "accepts a strictly valid DID, trimmed" do
      Process.put(:stub_response, {:ok, %{status: 200, body: @did <> "\n"}})
      assert {:ok, @did} = Handle.resolve_https("alice.example.com", http_client: StubHTTP)
    end

    test "refuses anything that merely starts with did:" do
      for body <- ["did:plc:abc", "did:web:Example.com", "did:example:123", "did:"] do
        Process.put(:stub_response, {:ok, %{status: 200, body: body}})

        assert {:error, :invalid_response} =
                 Handle.resolve_https("alice.example.com", http_client: StubHTTP),
               "accepted #{inspect(body)}"
      end
    end
  end
end
