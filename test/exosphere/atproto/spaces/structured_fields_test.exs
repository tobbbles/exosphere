defmodule Exosphere.ATProto.Spaces.StructuredFieldsTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Spaces.StructuredFields, as: SF

  test "parses the space headers' dictionaries, keeping item types apart" do
    assert {:ok, dict} =
             SF.parse_dictionary(
               ~s(ver=1, repo="did:example:alice", rev="3kbcq3p7ad400", data=:AQID:)
             )

    assert SF.get_bare(dict, "ver") == 1
    assert SF.get_bare(dict, "repo") == "did:example:alice"
    assert SF.get_bare(dict, "data") == {:bytes, <<1, 2, 3>>}

    # An unquoted value is a Token, not a String.
    assert {:ok, dict} = SF.parse_dictionary("tag=atproto-space-commit")
    assert SF.get_bare(dict, "tag") == {:token, "atproto-space-commit"}

    assert {:ok, dict} = SF.parse_dictionary("mac=:AAECAw==:, flag, n=-1.5")
    assert SF.get_bare(dict, "mac") == {:bytes, <<0, 1, 2, 3>>}
    assert SF.get_bare(dict, "flag") == true
    assert SF.get_bare(dict, "n") == -1.5
  end

  test "parses an Accept-Signature member: an inner list with item parameters" do
    input =
      ~s|mac=("atproto-space-commit";sf);keyid="did:key:zDnaExample";tag="atproto-space-commit"|

    assert {:ok, [{"mac", {:inner_list, items, params} = member}]} = SF.parse_dictionary(input)
    assert items == [{"atproto-space-commit", [{"sf", true}]}]
    assert params == [{"keyid", "did:key:zDnaExample"}, {"tag", "atproto-space-commit"}]

    assert "mac=" <> SF.serialize_member(member) == input
    assert SF.serialize_dictionary([{"mac", member}]) == input
  end

  test "parses inner lists with parameters and re-serializes them canonically" do
    input =
      ~s|sig1=("authorization"  "atproto-space-audience");tag="atproto-space-credential";created=1|

    assert {:ok, [{"sig1", {:inner_list, items, params} = member}]} =
             SF.parse_dictionary(input)

    assert items == [{"authorization", []}, {"atproto-space-audience", []}]
    assert params == [{"tag", "atproto-space-credential"}, {"created", 1}]

    assert SF.serialize_member(member) ==
             ~s|("authorization" "atproto-space-audience");tag="atproto-space-credential";created=1|
  end

  test "re-serializes a dictionary canonically, as the sf flag signs it" do
    {:ok, dict} = SF.parse_dictionary(~s(ver=1,   repo="did:a"  ,data=:AQ:;x=?1, flag))
    assert SF.serialize_dictionary(dict) == ~s(ver=1, repo="did:a", data=:AQ==:;x, flag)
  end

  test "a repeated key replaces the earlier value in place" do
    assert {:ok, [{"a", {3, []}}, {"b", {2, []}}]} = SF.parse_dictionary("a=1, b=2, a=3")
  end

  test "round-trips a dictionary" do
    dict = [
      {"ver", {1, []}},
      {"repo", {"did:example:alice", []}},
      {"data", {{:bytes, :crypto.strong_rand_bytes(32)}, []}}
    ]

    assert {:ok, ^dict} = SF.parse_dictionary(SF.serialize_dictionary(dict))
  end

  test "fails the whole field on malformed input" do
    for bad <- [
          "a=1,",
          "A=1",
          "a=\"unterminated",
          "a=(1 2",
          "a=:not base64!:",
          "a=1 b=2",
          "a=?2",
          "a=1234567890123456",
          "???"
        ] do
      assert {:error, :invalid_structured_field} = SF.parse_dictionary(bad), bad
    end
  end

  # RFC 9651 §4.1.5: fixed-point, never exponent notation (Erlang's shortest
  # float form writes 1500.0 as "1.5e3", which is not a Decimal).
  test "decimals serialize fixed-point and round-trip through parse" do
    for {input, canonical} <- [
          {"1000.0", "1000.0"},
          {"1500.0", "1500.0"},
          {"100000000000.0", "100000000000.0"},
          {"999999999999.999", "999999999999.999"},
          {"0.5", "0.5"},
          {"-12.250", "-12.25"},
          {"1.010", "1.01"}
        ] do
      assert {:ok, [{"x", {value, []}}] = dict} = SF.parse_dictionary("x=" <> input)
      assert is_float(value)
      assert SF.serialize_dictionary(dict) == "x=" <> canonical
      assert {:ok, ^dict} = SF.parse_dictionary(SF.serialize_dictionary(dict))
    end

    # A signature parameter re-serialized into the signature base.
    input =
      ~s[sig=("authorization" "atproto-space-audience");tag="atproto-space-credential";x=1500.0]

    assert {:ok, dict} = SF.parse_dictionary(input)
    assert SF.serialize_dictionary(dict) == input
  end

  test "decimals round to three places, half to even, and cap the integer part" do
    assert SF.serialize_dictionary([{"a", {0.0625, []}}]) == "a=0.062"
    assert SF.serialize_dictionary([{"a", {0.1875, []}}]) == "a=0.188"
    assert SF.serialize_dictionary([{"a", {2.0004, []}}]) == "a=2.0"
    assert SF.serialize_dictionary([{"a", {-0.0, []}}]) == "a=0.0"

    assert_raise ArgumentError, fn ->
      SF.serialize_dictionary([{"a", {1.0e12, []}}])
    end
  end

  test "string escapes" do
    assert {:ok, [{"a", {~s(say "hi" \\ bye), []}}]} =
             SF.parse_dictionary(~s(a="say \\"hi\\" \\\\ bye"))

    assert SF.serialize_dictionary([{"a", {~s(q"b\\), []}}]) == ~s(a="q\\"b\\\\")
  end
end
