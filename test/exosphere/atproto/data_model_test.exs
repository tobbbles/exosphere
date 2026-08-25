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
end
