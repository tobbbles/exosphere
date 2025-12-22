defmodule ExosphereTest do
  use ExUnit.Case

  test "Exosphere facade exposes TIDs" do
    tid = Exosphere.TID.generate()

    assert is_binary(tid)
    assert {:ok, _dt} = Exosphere.TID.to_datetime(tid)
  end

  test "Exosphere facade exposes XRPC client construction" do
    client = Exosphere.XRPC.Client.new("https://example.com")
    assert %Exosphere.ATProto.XRPC.Client{base_url: "https://example.com"} = client
  end
end
