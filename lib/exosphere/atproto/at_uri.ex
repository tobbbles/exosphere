defmodule Exosphere.ATProto.AtUri do
  @moduledoc """
  AT URI (`at://`) parsing and validation.

  AT URIs reference repositories, collections, and records, for example:

      at://did:plc:44ybard66vv44zksje25o7dz/app.bsky.feed.post/3jwdwj2ctlk26

  This module parses the restricted "well-behaved" form used in Lexicon records
  (see [the AT URI spec](https://atproto.com/specs/at-uri-scheme)):

      "at://" AUTHORITY [ "/" COLLECTION [ "/" RKEY ] ] [ "#" FRAGMENT ]

  where the authority is a DID or handle, the collection is an NSID, and the
  record key is a valid record key.

  ## Examples

      iex> Exosphere.ATProto.AtUri.parse("at://alice.example.com/app.bsky.feed.post/3jwdwj2ctlk26")
      {:ok, %Exosphere.ATProto.AtUri{authority: "alice.example.com", collection: "app.bsky.feed.post", rkey: "3jwdwj2ctlk26", fragment: nil}}

      iex> Exosphere.ATProto.AtUri.parse("https://example.com")
      {:error, :invalid_scheme}
  """

  alias Exosphere.ATProto.Identity.{DID, Handle}
  alias Exosphere.ATProto.{NSID, RecordKey}

  @max_length 8192

  @enforce_keys [:authority]
  defstruct [:authority, :collection, :rkey, :fragment]

  @type t :: %__MODULE__{
          authority: String.t(),
          collection: String.t() | nil,
          rkey: String.t() | nil,
          fragment: String.t() | nil
        }

  @type error ::
          :invalid_scheme
          | :too_long
          | :invalid_authority
          | :invalid_collection
          | :invalid_rkey
          | :rkey_without_collection
          | :invalid_at_uri

  @doc """
  Parse an AT URI string into an `%Exosphere.ATProto.AtUri{}` struct.
  """
  @spec parse(String.t()) :: {:ok, t()} | {:error, error()}
  def parse(uri) when is_binary(uri) do
    with :ok <- check_length(uri),
         {:ok, rest} <- strip_scheme(uri),
         {body, fragment} <- split_fragment(rest),
         {:ok, parts} <- split_path(body) do
      build(parts, fragment)
    end
  end

  def parse(_), do: {:error, :invalid_at_uri}

  @doc """
  Validate an AT URI string.
  """
  @spec valid?(String.t()) :: boolean()
  def valid?(uri) do
    match?({:ok, _}, parse(uri))
  end

  @doc """
  Render an `%Exosphere.ATProto.AtUri{}` struct back to its string form.
  """
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{} = uri) do
    [uri.authority, uri.collection, uri.rkey]
    |> Enum.reject(&is_nil/1)
    |> Enum.join("/")
    |> then(&("at://" <> &1))
    |> append_fragment(uri.fragment)
  end

  defp append_fragment(str, nil), do: str
  defp append_fragment(str, fragment), do: str <> "#" <> fragment

  defp check_length(uri) when byte_size(uri) <= @max_length, do: :ok
  defp check_length(_), do: {:error, :too_long}

  defp strip_scheme("at://" <> rest), do: {:ok, rest}
  defp strip_scheme(_), do: {:error, :invalid_scheme}

  defp split_fragment(rest) do
    case String.split(rest, "#", parts: 2) do
      [body] -> {body, nil}
      [body, fragment] -> {body, fragment}
    end
  end

  defp split_path(body) do
    case String.split(body, "/") do
      [authority] -> {:ok, {authority, nil, nil}}
      [authority, collection] -> {:ok, {authority, collection, nil}}
      [authority, collection, rkey] -> {:ok, {authority, collection, rkey}}
      _ -> {:error, :invalid_at_uri}
    end
  end

  defp build({authority, collection, rkey}, fragment) do
    with :ok <- validate_authority(authority),
         :ok <- validate_collection(collection),
         :ok <- validate_rkey(collection, rkey) do
      {:ok,
       %__MODULE__{
         authority: authority,
         collection: collection,
         rkey: rkey,
         fragment: fragment
       }}
    end
  end

  defp validate_authority(authority) do
    if DID.valid?(authority) or Handle.valid?(authority) do
      :ok
    else
      {:error, :invalid_authority}
    end
  end

  defp validate_collection(nil), do: :ok

  defp validate_collection(collection) do
    if NSID.valid?(collection), do: :ok, else: {:error, :invalid_collection}
  end

  defp validate_rkey(_collection, nil), do: :ok
  defp validate_rkey(nil, _rkey), do: {:error, :rkey_without_collection}

  defp validate_rkey(_collection, rkey) do
    if RecordKey.valid?(rkey), do: :ok, else: {:error, :invalid_rkey}
  end
end
