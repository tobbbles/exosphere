defmodule Exosphere.Interop.DataModelTest do
  @moduledoc """
  Conformance against the atproto interop DAG-CBOR data-model fixtures.

  The `data-model-fixtures` cases give a value (in the atproto JSON
  representation, using `$bytes`/`$link`) together with its canonical DAG-CBOR
  encoding and CID. Matching both byte-for-byte exercises the length-first key
  ordering, byte-string CID links, and minimal integer encoding.
  """
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.CBOR, as: DagCBOR
  alias Exosphere.ATProto.{CID, DataModel}
  alias Exosphere.Test.Interop

  @fixtures Interop.json("data-model/data-model-fixtures.json")

  test "encodes every fixture to the exact canonical DAG-CBOR bytes" do
    for fixture <- @fixtures do
      term = to_term(fixture["json"])
      expected = Base.decode64!(fixture["cbor_base64"], padding: false)

      assert {:ok, ^expected} = DagCBOR.encode(term),
             "CBOR bytes mismatch for: #{inspect(fixture["json"], limit: 5)}"
    end
  end

  test "computes the exact CID for every fixture" do
    for fixture <- @fixtures do
      term = to_term(fixture["json"])
      assert to_string(CID.create!(term)) == fixture["cid"]
    end
  end

  # Convert the atproto JSON representation into the term our encoder expects:
  #   {"$bytes": b64}  -> CBOR byte string
  #   {"$link": cid}   -> CID struct
  #   integer-valued floats -> integers (JSON has no integer/float distinction)
  defp to_term(%{"$bytes" => b64} = m) when map_size(m) == 1 do
    %CBOR.Tag{tag: :bytes, value: Base.decode64!(b64, padding: false)}
  end

  defp to_term(%{"$link" => link} = m) when map_size(m) == 1, do: CID.decode!(link)

  defp to_term(m) when is_map(m), do: Map.new(m, fn {k, v} -> {k, to_term(v)} end)
  defp to_term(l) when is_list(l), do: Enum.map(l, &to_term/1)

  defp to_term(f) when is_float(f) do
    truncated = trunc(f)
    if truncated == f, do: truncated, else: f
  end

  defp to_term(other), do: other

  describe "record/data-model validation" do
    test "accepts every valid fixture" do
      wrongly_rejected =
        "data-model/data-model-valid.json"
        |> Interop.json()
        |> Enum.filter(fn e -> DataModel.validate_record(e["json"]) != :ok end)

      assert wrongly_rejected == [],
             "valid data-model values rejected:
" <> format(wrongly_rejected)
    end

    test "rejects every invalid fixture" do
      wrongly_accepted =
        "data-model/data-model-invalid.json"
        |> Interop.json()
        |> Enum.filter(fn e -> DataModel.validate_record(e["json"]) == :ok end)

      assert wrongly_accepted == [],
             "invalid data-model values accepted:
" <> format(wrongly_accepted)
    end
  end

  defp format(entries) do
    Enum.map_join(entries, "
", &("  - " <> inspect(Map.get(&1, "note"))))
  end
end
