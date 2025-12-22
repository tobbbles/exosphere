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

  test "normalize/1 lowercases" do
    assert Handle.normalize("Alice.Example.COM") == "alice.example.com"
  end
end
