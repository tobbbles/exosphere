defmodule Exosphere.Interop.SyntaxTest do
  @moduledoc """
  Conformance against the atproto interop *syntax* tables: each identifier type
  has a list of strings that must be accepted and a list that must be rejected.
  """
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{AtUri, CID, NSID, RecordKey, TID}
  alias Exosphere.ATProto.Identity.{DID, Handle}
  alias Exosphere.Test.Interop

  # {label, valid_file, invalid_file}
  @cases [
    {"handle", "syntax/handle_syntax_valid.txt", "syntax/handle_syntax_invalid.txt"},
    {"did", "syntax/did_syntax_valid.txt", "syntax/did_syntax_invalid.txt"},
    {"nsid", "syntax/nsid_syntax_valid.txt", "syntax/nsid_syntax_invalid.txt"},
    {"recordkey", "syntax/recordkey_syntax_valid.txt", "syntax/recordkey_syntax_invalid.txt"},
    {"tid", "syntax/tid_syntax_valid.txt", "syntax/tid_syntax_invalid.txt"},
    {"aturi", "syntax/aturi_syntax_valid.txt", "syntax/aturi_syntax_invalid.txt"}
  ]

  defp check("handle", s), do: Handle.valid?(s)
  defp check("did", s), do: DID.valid?(s)
  defp check("nsid", s), do: NSID.valid?(s)
  defp check("recordkey", s), do: RecordKey.valid?(s)
  defp check("tid", s), do: TID.valid?(s)
  defp check("aturi", s), do: AtUri.valid?(s)

  for {label, valid_file, invalid_file} <- @cases do
    @label label
    @valid_file valid_file
    @invalid_file invalid_file

    describe "#{label} syntax" do
      test "accepts all valid strings" do
        wrongly_rejected =
          @valid_file
          |> Interop.lines()
          |> Enum.reject(fn s -> check(@label, s) end)

        assert wrongly_rejected == [],
               "#{@label}: valid strings rejected:\n" <> format(wrongly_rejected)
      end

      test "rejects all invalid strings" do
        wrongly_accepted =
          @invalid_file
          |> Interop.lines()
          |> Enum.filter(fn s -> check(@label, s) end)

        assert wrongly_accepted == [],
               "#{@label}: invalid strings accepted:\n" <> format(wrongly_accepted)
      end
    end
  end

  defp format(entries) do
    Enum.map_join(entries, "\n", &("  - " <> inspect(&1)))
  end

  # `CID.decode/1` implements only the atproto "blessed" CID format (CIDv1,
  # base32-lower, dag-cbor/raw codec, sha-256) — which is the only form that
  # appears in atproto records. The interop `cid_syntax_valid` table covers
  # *general* CID string syntax (base16/58/64 multibase, dag-pb, CIDv0, …), so
  # we don't accept all of it by design. We must, however, still reject every
  # malformed CID.
  describe "cid syntax (blessed-format subset)" do
    test "rejects all malformed CID strings" do
      wrongly_accepted =
        "syntax/cid_syntax_invalid.txt"
        |> Interop.lines()
        |> Enum.filter(fn s -> match?({:ok, _}, CID.decode(s)) end)

      assert wrongly_accepted == [],
             "cid: invalid strings accepted:\n" <> format(wrongly_accepted)
    end

    @tag :known_limitation
    test "general multibase/multicodec CID syntax is intentionally unsupported" do
      # Documents the gap: these are valid CID *strings* but not the blessed
      # format, so CID.decode/1 rejects them. If general CID parsing is added,
      # this should flip to asserting they all decode.
      not_blessed =
        "syntax/cid_syntax_valid.txt"
        |> Interop.lines()
        |> Enum.filter(fn s -> match?({:ok, _}, CID.decode(s)) end)

      assert not_blessed == []
    end
  end
end
