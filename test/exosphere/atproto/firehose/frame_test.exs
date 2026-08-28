defmodule Exosphere.ATProto.Firehose.FrameTest do
  use ExUnit.Case, async: true

  # Aliased under a distinct name so the bare `CBOR` below still refers to the
  # `:cbor` library, whose decode/1 returns the trailing bytes this needs.
  alias Exosphere.ATProto.CBOR, as: DagCBOR
  alias Exosphere.ATProto.Firehose.Frame

  describe "encode_message/2" do
    test "round-trips through decode/1" do
      payload = %{"seq" => 42, "did" => "did:plc:abc", "handle" => "alice.test"}

      assert {:ok, frame} = Frame.encode_message("#identity", payload)
      assert {:ok, %{op: 1, t: "#identity"}, ^payload} = Frame.decode(frame)
    end

    test "the frame is exactly two concatenated CBOR objects" do
      {:ok, frame} = Frame.encode_message("#info", %{"name" => "OutdatedCursor"})

      # Self-delimiting, so the header decode hands back the payload's bytes.
      assert {:ok, header, rest} = CBOR.decode(frame)
      assert header == %{"op" => 1, "t" => "#info"}
      assert {:ok, %{"name" => "OutdatedCursor"}} = DagCBOR.decode(rest)
    end

    test "carries bytes fields as CBOR byte strings" do
      # A text string here would corrupt every `blocks` field on the firehose.
      payload = %{"blocks" => %CBOR.Tag{tag: :bytes, value: <<1, 2, 3>>}}

      {:ok, frame} = Frame.encode_message("#commit", payload)
      assert {:ok, _header, decoded} = Frame.decode(frame)
      assert decoded["blocks"] == <<1, 2, 3>>
    end

    test "refuses a frame past the 5MB limit" do
      payload = %{"blocks" => %CBOR.Tag{tag: :bytes, value: :binary.copy(<<0>>, 5_000_001)}}

      assert {:error, {:frame_too_large, size}} = Frame.encode_message("#commit", payload)
      assert size > Frame.max_frame_bytes()
    end
  end

  describe "encode_error/2" do
    test "encodes op -1 with no type" do
      assert {:ok, frame} = Frame.encode_error("FutureCursor", "cursor in the future")

      assert {:ok, %{op: -1, t: nil}, payload} = Frame.decode(frame)
      assert payload == %{"error" => "FutureCursor", "message" => "cursor in the future"}
    end

    test "the message is optional" do
      assert {:ok, frame} = Frame.encode_error("ConsumerTooSlow")
      assert {:ok, %{op: -1}, %{"error" => "ConsumerTooSlow"} = payload} = Frame.decode(frame)
      refute Map.has_key?(payload, "message")
    end
  end

  describe "encode/2" do
    test "rejects a header it cannot make sense of" do
      assert {:error, {:invalid_header, _}} = Frame.encode(%{t: "#commit"}, %{})
      assert {:error, {:invalid_header, _}} = Frame.encode(%{op: 1}, %{})
    end

    test "passes a pre-built string-keyed header through" do
      assert {:ok, frame} = Frame.encode(%{"op" => 1, "t" => "#custom"}, %{"a" => 1})
      assert {:ok, %{op: 1, t: "#custom"}, %{"a" => 1}} = Frame.decode(frame)
    end
  end
end
