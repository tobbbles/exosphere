defmodule Exosphere.ATProto.OAuth.ScopeTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.Scope

  @space "com.example.group"
  @alice "did:plc:alice"
  @other "did:plc:bob"

  test "parse a bare type grant with its defaults" do
    assert {:ok, scope} = Scope.parse("space:" <> @space)

    assert scope == %Scope{
             type: @space,
             authority: :self,
             skey: :any,
             collections: [],
             actions: [:read, :create, :update, :delete],
             manage: []
           }

    assert Scope.to_string(scope) == "space:" <> @space
  end

  test "parse a wildcard type" do
    assert {:ok, scope} = Scope.parse("space:*")
    assert scope.type == :any
    assert Scope.to_string(scope) == "space:*"
  end

  test "parse every parameter" do
    assert {:ok, scope} =
             Scope.parse(
               "space:#{@space}?authority=#{@other}&skey=default&collection=com.example.groupPost&collection=com.example.groupNote&action=read&action=read_self&manage=update"
             )

    assert scope.authority == @other
    assert scope.skey == "default"
    assert scope.collections == ["com.example.groupNote", "com.example.groupPost"]
    assert scope.actions == [:read_self, :read]
    assert scope.manage == [:update]

    assert Scope.to_string(scope) ==
             "space:#{@space}?authority=#{@other}&skey=default&collection=com.example.groupNote&collection=com.example.groupPost&action=read_self&action=read&manage=update"
  end

  test "percent-encoded params decode like the reference" do
    assert {:ok, scope} = Scope.parse("space:#{@space}?authority=did%3Aplc%3Abob")
    assert scope.authority == "did:plc:bob"
    assert Scope.to_string(scope) == "space:#{@space}?authority=did:plc:bob"

    # Malformed percent-encoding falls through undecoded (and fails validation)
    assert {:error, :invalid_scope} = Scope.parse("space:#{@space}?authority=did%ZZlc")
  end

  test "collections collapse to * and dedupe" do
    assert {:ok, scope} =
             Scope.parse(
               "space:#{@space}?collection=com.example.groupPost&collection=*&collection=com.example.groupPost"
             )

    assert scope.collections == [:any]
    assert Scope.to_string(scope) == "space:#{@space}?collection=*"
  end

  test "unknown and malformed values are rejected" do
    for bad <- [
          "space:",
          "space",
          "space:not-an-nsid",
          "space:#{@space}?unknown=param",
          "space:#{@space}?type=" <> @space,
          "space:#{@space}?authority=not-a-did",
          "space:#{@space}?skey=..",
          "space:#{@space}?collection=not-an-nsid",
          "space:#{@space}?action=read&action=publish",
          "space:#{@space}?manage=read"
        ] do
      assert {:error, :invalid_scope} = Scope.parse(bad), "expected #{inspect(bad)} to be invalid"
    end
  end

  test "format round-trips through parse" do
    for good <- [
          "space:" <> @space,
          "space:*",
          "space:#{@space}?authority=*",
          "space:#{@space}?skey=default",
          "space:#{@space}?action=read",
          "space:#{@space}?action=read_self",
          "space:#{@space}?manage=create&manage=delete",
          "space:#{@space}?authority=#{@alice}&collection=*&action=create"
        ] do
      assert {:ok, scope} = Scope.parse(good)
      assert Scope.to_string(scope) == good
    end
  end

  describe "matches?/2" do
    setup do
      {:ok, scope: nil}
    end

    test "reads are all-or-nothing across collections" do
      {:ok, scope} = Scope.parse("space:#{@space}?action=read&authority=#{@alice}")

      assert Scope.matches?(scope, %{
               type: @space,
               authority: @alice,
               skey: "k",
               action: :read,
               collection: "com.example.groupPost"
             })

      assert Scope.matches?(scope, %{
               type: @space,
               authority: @alice,
               skey: "k",
               action: :read,
               collection: "anything.at.all"
             })
    end

    test "read implies read_self" do
      # (self must resolve first — unresolved self matches nothing)
      {:ok, read} = Scope.parse("space:#{@space}?action=read&authority=#{@alice}")
      {:ok, read_self} = Scope.parse("space:#{@space}?action=read_self&authority=#{@alice}")

      target = %{type: @space, authority: @alice, skey: "k", action: :read_self}

      assert Scope.matches?(read, target)
      assert Scope.matches?(read_self, target)
      # but read_self does not imply read
      refute Scope.matches?(read_self, %{target | action: :read})
    end

    test "writes need the action and a covering collection" do
      {:ok, scope} =
        Scope.parse(
          "space:#{@space}?collection=com.example.groupPost&action=create&authority=#{@alice}"
        )

      assert Scope.matches?(scope, %{
               type: @space,
               authority: @alice,
               skey: "k",
               action: :create,
               collection: "com.example.groupPost"
             })

      refute Scope.matches?(scope, %{
               type: @space,
               authority: @alice,
               skey: "k",
               action: :create,
               collection: "com.example.groupNote"
             })

      refute Scope.matches?(scope, %{
               type: @space,
               authority: @alice,
               skey: "k",
               action: :delete,
               collection: "com.example.groupPost"
             })
    end

    test "an empty collection list grants no writes" do
      {:ok, scope} = Scope.parse("space:#{@space}?authority=#{@alice}")

      refute Scope.matches?(scope, %{
               type: @space,
               authority: @alice,
               skey: "k",
               action: :create,
               collection: "com.example.groupPost"
             })

      assert Scope.matches?(scope, %{type: @space, authority: @alice, skey: "k", action: :read})
    end

    test "type, authority, and skey narrow the space" do
      {:ok, any} = Scope.parse("space:*?authority=*&skey=*")

      assert Scope.matches?(any, %{
               type: "other.type",
               authority: @other,
               skey: "x",
               action: :read
             })

      {:ok, narrow} = Scope.parse("space:#{@space}?skey=default&authority=#{@alice}")

      refute Scope.matches?(narrow, %{
               type: @space,
               authority: @alice,
               skey: "other",
               action: :read
             })

      assert Scope.matches?(narrow, %{
               type: @space,
               authority: @alice,
               skey: "default",
               action: :read
             })
    end

    test "an unresolved self authority matches nothing" do
      {:ok, scope} = Scope.parse("space:#{@space}")
      refute Scope.matches?(scope, %{type: @space, authority: @alice, skey: "k", action: :read})
    end

    test "manage operations map independently of actions" do
      # read_self is the narrowest record action, so manage is what carries this grant
      {:ok, scope} =
        Scope.parse("space:#{@space}?manage=update&authority=#{@alice}&action=read_self")

      assert Scope.matches?(scope, %{type: @space, authority: @alice, skey: "k", manage: :update})
      refute Scope.matches?(scope, %{type: @space, authority: @alice, skey: "k", manage: :delete})
      refute Scope.matches?(scope, %{type: @space, authority: @alice, skey: "k", action: :read})
    end
  end

  test "with_default_collections materializes declared collections at issuance" do
    {:ok, scope} = Scope.parse("space:#{@space}")

    resolved =
      Scope.with_default_collections(scope, ["com.example.groupPost", "com.example.groupNote"])

    assert resolved.collections == ["com.example.groupNote", "com.example.groupPost"]
    # An explicit grant is never overridden.
    explicit =
      Scope.with_default_collections(%Scope{scope | collections: [:any]}, [
        "com.example.groupPost"
      ])

    assert explicit.collections == [:any]
    # Nor is an empty declaration.
    assert Scope.with_default_collections(scope, []).collections == []

    # With collections materialized, writes to them are now covered.
    resolved = Scope.with_resolved_authority(resolved, @alice)

    assert Scope.matches?(resolved, %{
             type: @space,
             authority: @alice,
             skey: "k",
             action: :create,
             collection: "com.example.groupPost"
           })
  end

  test "with_resolved_authority binds self to the granting user" do
    {:ok, scope} = Scope.parse("space:#{@space}")
    resolved = Scope.with_resolved_authority(scope, @alice)
    assert resolved.authority == @alice
    assert Scope.matches?(resolved, %{type: @space, authority: @alice, skey: "k", action: :read})
    refute Scope.matches?(resolved, %{type: @space, authority: @other, skey: "k", action: :read})

    # A concrete authority is untouched.
    {:ok, other} = Scope.parse("space:#{@space}?authority=#{@other}")
    assert Scope.with_resolved_authority(other, @alice).authority == @other
  end
end
