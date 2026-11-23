defmodule Exosphere.ATProto.DataModelTest do
  @moduledoc """
  Unit coverage for the `$bytes` wrapper's base64 enforcement.
  """

  use ExUnit.Case, async: true

  alias Exosphere.ATProto.DataModel

  describe "$bytes validation" do
    test "accepts unpadded standard-alphabet base64" do
      assert :ok = DataModel.validate_record(%{"$bytes" => "aGk"})
      assert :ok = DataModel.validate_record(%{"$bytes" => "Zm9vYmFy"})

      # Same shape the atproto interop data-model fixtures use (43 chars,
      # standard alphabet including + and /).
      assert :ok =
               DataModel.validate_record(%{
                 "$bytes" => "nFERjvLLiw9qm45JrqH9QTzyC2Lu1Xb4ne6+sBrCzI0"
               })
    end

    test "rejects non-binary values" do
      assert {:error, {"$bytes", :invalid_field_type}} =
               DataModel.validate_record(%{
                 "$bytes" => [1, 2, 3]
               })
    end

    test "rejects invalid base64 with the path and reason" do
      assert {:error, {"$bytes", :invalid_base64}} =
               DataModel.validate_record(%{"$bytes" => "!!not base64!!"})

      # Length must not be congruent to 1 mod 4.
      assert {:error, {"$bytes", :invalid_base64}} = DataModel.validate_record(%{"$bytes" => "a"})

      # base64url is a different alphabet than the data model specifies.
      assert {:error, {"$bytes", :invalid_base64}} =
               DataModel.validate_record(%{"$bytes" => "a-b_cd"})
    end

    test "rejects padded base64 — the spec form is unpadded" do
      assert {:error, {"$bytes", :invalid_base64}} =
               DataModel.validate_record(%{"$bytes" => "aGk="})

      assert {:error, {"$bytes", :invalid_base64}} =
               DataModel.validate_record(%{"$bytes" => "Zm9vYg=="})
    end

    test "reports the full path for nested byte strings" do
      assert {:error, {"rcrd.$bytes", :invalid_base64}} =
               DataModel.validate_record(%{"rcrd" => %{"$bytes" => "!!"}})

      assert {:error, {"rcrd.a[0].$bytes", :invalid_base64}} =
               DataModel.validate_record(%{"rcrd" => %{"a" => [%{"$bytes" => "!!"}]}})
    end
  end

  describe "integer range (signed 64-bit)" do
    test "accepts the int64 bounds" do
      assert :ok = DataModel.validate_record(%{"a" => 9_223_372_036_854_775_807})
      assert :ok = DataModel.validate_record(%{"a" => -9_223_372_036_854_775_808})
    end

    test "rejects one past either bound, with the path" do
      assert {:error, {"a", :integer_out_of_range}} =
               DataModel.validate_record(%{"a" => 9_223_372_036_854_775_808})

      assert {:error, {"a[1]", :integer_out_of_range}} =
               DataModel.validate_record(%{"a" => [1, -9_223_372_036_854_775_809]})
    end

    test "blob size is range-checked like any integer" do
      blob = %{
        "$type" => "blob",
        "ref" => %{"$link" => "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity"},
        "mimeType" => "image/png",
        "size" => 2 ** 64
      }

      assert {:error, {"b.size", :integer_out_of_range}} =
               DataModel.validate_record(%{"b" => blob})
    end
  end

  describe "map keys" do
    test "rejects an empty key, at any depth" do
      assert {:error, {"", :empty_map_key}} = DataModel.validate_record(%{"" => 1})
      assert {:error, {"a", :empty_map_key}} = DataModel.validate_record(%{"a" => %{"" => 1}})

      assert {:error, {"a[0]", :empty_map_key}} =
               DataModel.validate_record(%{"a" => [%{"" => 1}]})
    end

    test "unknown $-prefixed keys are ignored, as the spec asks" do
      assert :ok = DataModel.validate_record(%{"$future" => 1, "a" => 2})
    end
  end

  describe "nesting depth" do
    defp nest(0), do: 1
    defp nest(n), do: %{"a" => nest(n - 1)}

    defp nest_list(0), do: 1
    defp nest_list(n), do: [nest_list(n - 1)]

    test "accepts 32 levels and rejects 33" do
      assert DataModel.max_depth() == 32
      assert :ok = DataModel.validate_record(nest(32))
      assert {:error, {_path, :max_depth_exceeded}} = DataModel.validate_record(nest(33))
    end

    test "lists count towards the depth" do
      assert :ok = DataModel.validate_record(%{"a" => nest_list(31)})

      assert {:error, {_path, :max_depth_exceeded}} =
               DataModel.validate_record(%{"a" => nest_list(32)})
    end

    test "a hostile deep value fails fast" do
      assert {:error, {_path, :max_depth_exceeded}} = DataModel.validate_record(nest(100_000))
    end
  end

  describe "the interop invalid shapes" do
    @cid "bafkreiccldh766hwcnuxnf2wh6jgzepf2nlu2lvcllt63eww5p6chi4ity"

    test "$link with an extra field" do
      assert {:error, {"l.$link", :wrapper_with_extra_fields}} =
               DataModel.validate_record(%{"l" => %{"$link" => @cid, "extra" => 1}})
    end

    test "$bytes with an extra field" do
      assert {:error, {"b.$bytes", :wrapper_with_extra_fields}} =
               DataModel.validate_record(%{"b" => %{"$bytes" => "aGk", "a" => 1}})
    end

    test "empty $type" do
      assert {:error, {"$type", :empty_type}} = DataModel.validate_record(%{"$type" => ""})
    end

    test "blob with a string size" do
      blob = %{
        "$type" => "blob",
        "ref" => %{"$link" => @cid},
        "mimeType" => "image/png",
        "size" => "12"
      }

      assert {:error, {"b.size", :invalid_field_type}} = DataModel.validate_record(%{"b" => blob})
    end
  end
end
