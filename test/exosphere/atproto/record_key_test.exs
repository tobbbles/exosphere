defmodule Exosphere.ATProto.RecordKeyTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.RecordKey

  test "valid?/1 accepts allowed record keys" do
    assert RecordKey.valid?("3jzfcijpj2z2a")
    assert RecordKey.valid?("self")
    assert RecordKey.valid?("literal:self")
    assert RecordKey.valid?("foo-bar_baz.qux~1")
    assert RecordKey.valid?("A")
    assert RecordKey.valid?(String.duplicate("a", 512))
  end

  test "valid?/1 rejects disallowed record keys" do
    assert RecordKey.valid?(".") == false
    assert RecordKey.valid?("..") == false
    assert RecordKey.valid?("") == false
    assert RecordKey.valid?(String.duplicate("a", 513)) == false
    # disallowed characters
    assert RecordKey.valid?("foo/bar") == false
    assert RecordKey.valid?("foo bar") == false
    assert RecordKey.valid?("foo@bar") == false
    assert RecordKey.valid?(nil) == false
  end
end
