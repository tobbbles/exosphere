defmodule Exosphere.ATProto do
  @moduledoc """
  Lower-level, spec-aligned AT Protocol (ATProto) building blocks.

  This namespace is intended to stay close to the AT Protocol specifications
  (see [atproto.com](https://atproto.com/)): one submodule per spec domain
  (`NSID`, `RecordKey`, `AtUri`, `TID`, `CBOR`, `CID`, `CAR`, `MST`,
  `DataModel`, …), with `Identity` and `Repo` grouping their own submodules.

  The namespace root is the protocol's front door: it composes the submodules
  into protocol-level entry points without implementing anything itself.
  `validate/2` dispatches to the spec-aligned validators so callers don't need
  to know which submodule owns which grammar:

      :ok = Exosphere.ATProto.validate(:nsid, "app.bsky.feed.post")
      :ok = Exosphere.ATProto.validate(:record, %{"$type" => "com.example.post"})

  For higher-level, end-user APIs (XRPC clients, firehose, etc.), prefer the
  `Exosphere.*` facade modules, which compose these building blocks.
  """

  alias Exosphere.ATProto.{AtUri, CID, DataModel, MST, NSID, RecordKey, TID}
  alias Exosphere.ATProto.Identity.{DID, Handle}

  @type validation_kind ::
          :nsid | :rkey | :at_uri | :tid | :did | :handle | :cid | :mst_key | :record

  @doc """
  Validate a value against an AT Protocol grammar or data model.

  Dispatches to the submodule validator that owns each kind, normalizing
  their boolean/`{:error, _}` returns into `:ok | {:error, reason}`:

  | Kind | Validates | Owner |
  |------|-----------|-------|
  | `:nsid` | NSID syntax | `NSID` |
  | `:rkey` | record key syntax | `RecordKey` |
  | `:at_uri` | `at://` URI syntax | `AtUri` |
  | `:tid` | TID syntax | `TID` |
  | `:did` | DID syntax | `Identity.DID` |
  | `:handle` | handle syntax | `Identity.Handle` |
  | `:cid` | CID string (blessed atproto format) | `CID` |
  | `:mst_key` | MST record path (`nsid/rkey`) | `MST` |
  | `:record` | atproto data-model record | `DataModel` |

  ## Examples

      iex> Exosphere.ATProto.validate(:nsid, "app.bsky.feed.post")
      :ok

      iex> Exosphere.ATProto.validate(:tid, "not-a-tid")
      {:error, :invalid_tid}

      iex> Exosphere.ATProto.validate(:record, %{"a" => 1.5})
      {:error, {"a", :non_integral_float}}
  """
  @spec validate(validation_kind(), term()) :: :ok | {:error, term()}
  def validate(kind, value)

  def validate(:nsid, value), do: boolean_result(NSID.valid?(value), :invalid_nsid)
  def validate(:rkey, value), do: boolean_result(RecordKey.valid?(value), :invalid_rkey)
  def validate(:at_uri, value), do: boolean_result(AtUri.valid?(value), :invalid_at_uri)
  def validate(:tid, value), do: boolean_result(TID.valid?(value), :invalid_tid)
  def validate(:did, value), do: boolean_result(DID.valid?(value), :invalid_did)
  def validate(:handle, value), do: boolean_result(Handle.valid?(value), :invalid_handle)
  def validate(:mst_key, value), do: boolean_result(MST.valid_key?(value), :invalid_mst_key)

  def validate(:cid, value) do
    case CID.decode(value) do
      {:ok, _cid} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  def validate(:record, value), do: DataModel.validate_record(value)

  def validate(kind, _value) when is_atom(kind),
    do: {:error, {:unknown_validation_kind, kind}}

  def validate(_kind, _value), do: {:error, :unknown_validation_kind}

  defp boolean_result(true, _reason), do: :ok
  defp boolean_result(false, reason), do: {:error, reason}
end
