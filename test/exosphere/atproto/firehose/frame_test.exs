defmodule Exosphere.ATProto.Firehose.FrameTest do
  @moduledoc """
  Server-side frame encoding, checked by decoding the frames again on the
  client path: `Frame.decode/1`, and the consumer's own `handle_frame/2`, which
  runs `Frame.decode/1` and `Message.decode/2` and dispatches to `:on_event`.
  """

  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Exosphere.ATProto.{Crypto, Label}
  alias Exosphere.ATProto.Firehose.{Consumer, Frame}

  doctest Frame

  @label %{
    "ver" => 1,
    "src" => "did:plc:labeler",
    "uri" => "at://did:plc:author/pub.example.post/3lk2",
    "cid" => "bafyreihu6jo2nciwlckipwfjebgcvqusfqwv6kljvjtvntd2g3gpkhap4q",
    "val" => "ai-text",
    "cts" => "2026-11-09T12:00:00.000Z"
  }

  setup do
    {:ok, %{private_key: priv, public_key: pub}} = Crypto.generate_keypair(:secp256k1)
    {:ok, signed} = Label.sign(@label, priv, :secp256k1)
    %{signed: signed, pub: pub}
  end

  # A consumer state whose callback hands each message to the test process.
  defp consumer do
    test = self()

    %Consumer{
      relay_url: "wss://labeler.example.com",
      method: "com.atproto.label.subscribeLabels",
      cursor: nil,
      on_event: fn message, state ->
        send(test, {:event, message})
        state
      end,
      stats: %{frames: 0, messages: 0, errors: 0, started_at: 0}
    }
  end

  defp through_consumer(frame) do
    {:ok, state} = Consumer.handle_frame({:binary, frame}, consumer())
    state
  end

  # The frame's two CBOR objects, decoded by the raw :cbor library, so byte
  # strings stay distinguishable from text strings (`%CBOR.Tag{tag: :bytes}`).
  # Frame.decode/1 unwraps both to plain binaries.
  defp raw(frame) do
    {:ok, header, rest} = CBOR.decode(frame)
    {:ok, payload, ""} = CBOR.decode(rest)
    {header, payload}
  end

  describe "encode_labels/2" do
    test "a signed label survives the round trip and still verifies", %{signed: signed, pub: pub} do
      assert {:ok, frame} = Frame.encode_labels(5, [signed])

      state = through_consumer(frame)

      assert_received {:event, %{type: :labels, seq: 5, labels: [label]}}
      assert label == signed
      assert :ok = Label.verify_with_key(label, pub, :secp256k1)
      assert state.cursor == 5
      assert state.stats.errors == 0
    end

    test "writes the header as op 1, t #labels", %{signed: signed} do
      {:ok, frame} = Frame.encode_labels(5, [signed])

      assert {%{"op" => 1, "t" => "#labels"}, _payload} = raw(frame)
      assert {:ok, %{op: 1, t: "#labels"}, %{"seq" => 5}} = Frame.decode(frame)
    end

    test "the header is canonical DAG-CBOR: keys length-first" do
      {:ok, frame} = Frame.encode_labels(1, [])

      # map(2), "t" => "#labels", "op" => 1: "t" sorts before "op".
      header = <<0xA2, 0x61, "t", 0x67, "#labels", 0x62, "op", 0x01>>
      assert binary_part(frame, 0, byte_size(header)) == header
    end

    test "sig goes on the wire as a byte string", %{signed: signed} do
      {:ok, frame} = Frame.encode_labels(5, [signed])

      {_header, %{"labels" => [label]}} = raw(frame)
      assert %CBOR.Tag{tag: :bytes, value: sig} = label["sig"]
      assert sig == signed["sig"]
    end

    test "a $bytes sig comes out as raw bytes, padded or not", %{signed: signed, pub: pub} do
      for b64 <- [Base.encode64(signed["sig"]), Base.encode64(signed["sig"], padding: false)] do
        json_form = %{signed | "sig" => %{"$bytes" => b64}}
        {:ok, frame} = Frame.encode_labels(9, [json_form])

        {_header, %{"labels" => [wire]}} = raw(frame)
        assert %CBOR.Tag{tag: :bytes, value: sig} = wire["sig"]
        assert sig == signed["sig"]

        through_consumer(frame)
        assert_received {:event, %{type: :labels, labels: [label]}}
        assert label == signed
        assert :ok = Label.verify_with_key(label, pub, :secp256k1)
      end
    end

    test "nil fields are left out, and the label still verifies", %{signed: signed, pub: pub} do
      {:ok, frame} = Frame.encode_labels(2, [Map.put(signed, "exp", nil)])

      {:ok, _header, %{"labels" => [label]}} = Frame.decode(frame)
      refute Map.has_key?(label, "exp")
      assert :ok = Label.verify_with_key(label, pub, :secp256k1)
    end

    test "neg: false is kept, since a labeler that included it signed it" do
      {:ok, frame} = Frame.encode_labels(3, [Map.put(@label, "neg", false)])

      {:ok, _header, %{"labels" => [label]}} = Frame.decode(frame)
      assert label["neg"] == false
    end

    test "keeps label order across a batch", %{signed: signed} do
      labels = for val <- ~w(a b c), do: %{signed | "val" => val}
      {:ok, frame} = Frame.encode_labels(4, labels)

      {:ok, _header, %{"labels" => decoded}} = Frame.decode(frame)
      assert Enum.map(decoded, & &1["val"]) == ~w(a b c)
    end

    test "an unsigned label is passed through without a sig" do
      {:ok, frame} = Frame.encode_labels(6, [@label])

      {:ok, _header, %{"labels" => [label]}} = Frame.decode(frame)
      assert label == @label
    end

    test "rejects a bad sig, naming the label", %{signed: signed} do
      bad = %{signed | "sig" => %{"$bytes" => "not base64!"}}

      assert {:error, {:invalid_label, 1, :invalid_sig}} =
               Frame.encode_labels(7, [signed, bad])

      assert {:error, {:invalid_label, 0, :invalid_sig}} =
               Frame.encode_labels(7, [%{signed | "sig" => 42}])
    end

    test "rejects a label that is not a map" do
      assert {:error, {:invalid_label, 0, :not_a_map}} = Frame.encode_labels(7, ["nope"])
    end

    test "rejects a seq that is not a positive integer" do
      assert {:error, :invalid_seq} = Frame.encode_labels(0, [])
      assert {:error, :invalid_seq} = Frame.encode_labels("1", [])
    end

    test "refuses floats, which DAG-CBOR does not allow" do
      assert {:error, :floats_not_allowed} = Frame.encode_labels(8, [%{"ver" => 1.0}])
    end
  end

  describe "encode_info/2" do
    test "round-trips through the consumer as an #info message" do
      {:ok, frame} = Frame.encode_info("OutdatedCursor", "cursor is older than the stream")

      state = through_consumer(frame)

      assert_received {:event,
                       %{
                         type: :info,
                         name: "OutdatedCursor",
                         message: "cursor is older than the stream"
                       }}

      # #info carries no seq, so the tracked cursor does not move.
      assert state.cursor == nil
    end

    test "leaves out a nil message" do
      {:ok, frame} = Frame.encode_info("OutdatedCursor")

      assert {:ok, %{op: 1, t: "#info"}, payload} = Frame.decode(frame)
      assert payload == %{"name" => "OutdatedCursor"}
    end
  end

  describe "encode_error/2" do
    test "writes op -1 with no t, and an error payload" do
      {:ok, frame} = Frame.encode_error("FutureCursor", "Cursor is ahead of the stream")

      assert {header, payload} = raw(frame)
      assert header == %{"op" => -1}
      assert payload == %{"error" => "FutureCursor", "message" => "Cursor is ahead of the stream"}

      assert {:ok, %{op: -1, t: nil}, ^payload} = Frame.decode(frame)
    end

    test "leaves out a nil message" do
      {:ok, frame} = Frame.encode_error("FutureCursor")
      assert {:ok, %{op: -1}, %{"error" => "FutureCursor"} = payload} = Frame.decode(frame)
      refute Map.has_key?(payload, "message")
    end

    test "the consumer counts it as a server error and dispatches nothing" do
      {:ok, frame} = Frame.encode_error("FutureCursor")

      log =
        capture_log(fn ->
          state = through_consumer(frame)
          assert state.stats.errors == 1
        end)

      assert log =~ "FutureCursor"
      refute_received {:event, _}
    end

    test "rejects a namespaced or #-prefixed error name" do
      assert {:error, :invalid_error_name} = Frame.encode_error("#FutureCursor")

      assert {:error, :invalid_error_name} =
               Frame.encode_error("com.atproto.label.subscribeLabels#FutureCursor")

      assert {:error, :invalid_error_name} = Frame.encode_error("")
    end
  end

  describe "encode_message/2" do
    test "rejects a type that is not a #fragment" do
      assert {:error, :invalid_type} = Frame.encode_message("labels", %{})
      assert {:error, :invalid_type} = Frame.encode_message("#", %{})
    end

    test "rejects a payload that is not a map" do
      assert {:error, :invalid_payload} = Frame.encode_message("#labels", [])
    end

    test "an unknown type still decodes, as a raw map with :type" do
      {:ok, frame} = Frame.encode_message("#future", %{"x" => 1})
      through_consumer(frame)

      assert_received {:event, %{"x" => 1, type: "#future"}}
    end
  end
end
