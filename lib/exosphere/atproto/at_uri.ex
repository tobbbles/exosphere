defmodule Exosphere.ATProto.AtUri do
  @moduledoc """
  AT URI (`at://`) parsing and validation, covering both the public and the
  permissioned-data ("space") grammars.

  AT URIs reference repositories, collections, and records, for example:

      at://did:plc:44ybard66vv44zksje25o7dz/app.bsky.feed.post/3jwdwj2ctlk26

  This module parses the restricted "well-behaved" form used in Lexicon records
  (see [the AT URI spec](https://atproto.com/specs/at-uri-scheme)):

      "at://" AUTHORITY [ "/" COLLECTION [ "/" RKEY ] ] [ "#" FRAGMENT ]

  where the authority is a DID or handle, the collection is an NSID, and the
  record key is a valid record key.

  ## Space URIs

  Spaces (atproto permissioned data, proposal 0016) add a second grammar. A
  space URI replaces the collection segment with the literal `space` marker and
  addresses a space, or a record inside a member's permissioned repo:

      at://{spaceDid}/space/{spaceType}/{skey}
      at://{spaceDid}/space/{spaceType}/{skey}/{authorDid}/{collection}/{rkey}

  On a space URI the `authority` field holds the *space authority* DID (a
  handle is not valid there), `space_type`, `skey` and — for the record form —
  `author` hold the space segments, and `collection`/`rkey` still address the
  record. The record segments are all-or-none: a space URI either stops at the
  `skey` (a space reference) or carries `author`, `collection` and `rkey`
  together, mirroring the reference implementation's strict validator.

  The two grammars are never confusable: a public collection is an NSID, which
  always contains at least two dots, while the `space` marker contains none.
  `space?/1` is the discriminator; a parsed URI always satisfies exactly one
  grammar.

  ## Examples

      iex> Exosphere.ATProto.AtUri.parse("at://alice.example.com/app.bsky.feed.post/3jwdwj2ctlk26")
      {:ok, %Exosphere.ATProto.AtUri{authority: "alice.example.com", collection: "app.bsky.feed.post", rkey: "3jwdwj2ctlk26", fragment: nil}}

      iex> {:ok, uri} = Exosphere.ATProto.AtUri.parse("at://did:plc:abc/space/com.example.group/default")
      iex> uri.space_type
      "com.example.group"
      iex> uri.skey
      "default"

      iex> Exosphere.ATProto.AtUri.parse("https://example.com")
      {:error, :invalid_scheme}
  """

  alias Exosphere.ATProto.Identity.{DID, Handle}
  alias Exosphere.ATProto.{NSID, RecordKey}

  @max_length 8192
  @space_marker "space"

  @enforce_keys [:authority]
  defstruct [:authority, :collection, :rkey, :fragment, :space_type, :skey, :author]

  @type t :: %__MODULE__{
          authority: String.t(),
          collection: String.t() | nil,
          rkey: String.t() | nil,
          fragment: String.t() | nil,
          space_type: String.t() | nil,
          skey: String.t() | nil,
          author: String.t() | nil
        }

  @type error ::
          :invalid_scheme
          | :too_long
          | :invalid_authority
          | :invalid_collection
          | :invalid_rkey
          | :rkey_without_collection
          | :invalid_fragment
          | :invalid_space_type
          | :invalid_skey
          | :invalid_author
          | :not_a_space_uri
          | :invalid_at_uri

  @doc """
  Parse an AT URI string (either grammar) into an `%Exosphere.ATProto.AtUri{}`.

  Space URIs require a DID authority; on the public grammar a handle is also
  accepted.
  """
  @spec parse(String.t()) :: {:ok, t()} | {:error, error()}
  def parse(uri) when is_binary(uri) do
    with :ok <- check_length(uri),
         {:ok, rest} <- strip_scheme(uri),
         {:ok, body, fragment} <- split_fragment(rest),
         {:ok, grammar, authority, segments} <- split_path(body) do
      build(grammar, authority, segments, fragment)
    end
  end

  def parse(_), do: {:error, :invalid_at_uri}

  @doc """
  Validate an AT URI string (either grammar).
  """
  @spec valid?(String.t()) :: boolean()
  def valid?(uri) do
    match?({:ok, _}, parse(uri))
  end

  @doc """
  Whether the URI uses the space (permissioned-data) grammar.

  The discriminator between the two grammars: exactly one of `space?/1` and the
  public form (nil `space_type`) holds for any URI produced by `parse/1`.
  """
  @spec space?(t()) :: boolean()
  def space?(%__MODULE__{space_type: space_type}), do: space_type != nil

  @doc """
  Build a space-reference URI: `at://{spaceDid}/space/{spaceType}/{skey}`.
  """
  @spec make_space(String.t(), String.t(), String.t()) :: {:ok, t()} | {:error, error()}
  def make_space(space_did, space_type, skey) do
    with :ok <- validate_space_did(space_did),
         :ok <- validate_space_type(space_type),
         :ok <- validate_skey(skey) do
      {:ok,
       %__MODULE__{
         authority: space_did,
         space_type: space_type,
         skey: skey
       }}
    end
  end

  @doc """
  Build a space record URI, addressing a record in a member's permissioned
  repo. The author DID, collection, and record key are all required — partial
  record forms do not exist in the space grammar.
  """
  @spec make_space(String.t(), String.t(), String.t(), String.t(), String.t(), String.t()) ::
          {:ok, t()} | {:error, error()}
  def make_space(space_did, space_type, skey, author, collection, rkey) do
    with {:ok, ref} <- make_space(space_did, space_type, skey),
         :ok <- validate_author(author),
         :ok <- validate_collection(collection),
         :ok <- validate_rkey(collection, rkey) do
      {:ok, %__MODULE__{ref | author: author, collection: collection, rkey: rkey}}
    end
  end

  @doc """
  The space-reference form of a space URI: the same space, with any record
  segments dropped. The identity of the space a record lives in.

  Returns `{:error, :not_a_space_uri}` for public-grammar URIs.
  """
  @spec space_ref(t()) :: {:ok, t()} | {:error, :not_a_space_uri}
  def space_ref(%__MODULE__{space_type: nil}), do: {:error, :not_a_space_uri}

  def space_ref(%__MODULE__{} = uri),
    do: {:ok, %__MODULE__{uri | author: nil, collection: nil, rkey: nil}}

  @doc """
  Render an `%Exosphere.ATProto.AtUri{}` struct back to its string form,
  following whichever grammar the struct inhabits.

  Raises `ArgumentError` for structs that mix the two grammars — e.g. a space
  `space_type` with public-only fields, or a partial record form — since those
  have no valid string rendering and can only arise from constructing the
  struct by hand.
  """
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{space_type: nil} = uri) do
    if uri.skey != nil or uri.author != nil do
      raise ArgumentError,
            "public AT URI cannot carry space segments (skey/author): #{inspect(uri)}"
    end

    [uri.authority, uri.collection, uri.rkey]
    |> Enum.reject(&is_nil/1)
    |> Enum.join("/")
    |> then(&("at://" <> &1))
    |> append_fragment(uri.fragment)
  end

  def to_string(%__MODULE__{} = uri) do
    %__MODULE__{space_type: space_type, skey: skey} = uri
    record = [uri.author, uri.collection, uri.rkey]

    cond do
      skey == nil ->
        raise ArgumentError, "space AT URI requires an skey: #{inspect(uri)}"

      complete_record?(record) ->
        segments =
          [uri.authority, @space_marker, space_type, skey | Enum.reject(record, &is_nil/1)]

        segments
        |> Enum.join("/")
        |> then(&("at://" <> &1))
        |> append_fragment(uri.fragment)

      true ->
        raise ArgumentError,
              "space AT URI record segments are all-or-none (author/collection/rkey): #{inspect(uri)}"
    end
  end

  # The record segments either address a record in full or are absent entirely;
  # anything in between has no valid rendering.
  defp complete_record?([nil, nil, nil]), do: true

  defp complete_record?([author, collection, rkey])
       when is_binary(author) and is_binary(collection) and is_binary(rkey),
       do: true

  defp complete_record?(_), do: false

  defp append_fragment(str, nil), do: str
  defp append_fragment(str, fragment), do: str <> "#" <> fragment

  defp check_length(uri) when byte_size(uri) <= @max_length, do: :ok
  defp check_length(_), do: {:error, :too_long}

  defp strip_scheme("at://" <> rest), do: {:ok, rest}
  defp strip_scheme(_), do: {:error, :invalid_scheme}

  # At most one '#' is allowed. A present fragment must be non-empty and contain
  # no whitespace (AT URIs never contain whitespace).
  defp split_fragment(rest) do
    case String.split(rest, "#") do
      [body] -> {:ok, body, nil}
      [body, fragment] -> validate_fragment(body, fragment)
      _ -> {:error, :invalid_fragment}
    end
  end

  defp validate_fragment(body, fragment) do
    if fragment != "" and not Regex.match?(~r/\s/, fragment) do
      {:ok, body, fragment}
    else
      {:error, :invalid_fragment}
    end
  end

  # The first path segment decides the grammar. A leading "space" marker can
  # never be a public collection (NSIDs contain at least two dots), so the
  # dispatch is unambiguous.
  defp split_path(body) do
    case String.split(body, "/") do
      [authority] ->
        {:ok, :public, authority, []}

      [authority, first | rest] when first == @space_marker ->
        {:ok, :space, authority, rest}

      [authority | rest] ->
        {:ok, :public, authority, rest}

      _ ->
        {:error, :invalid_at_uri}
    end
  end

  defp build(:public, authority, segments, fragment) do
    case segments do
      [] -> build_public(authority, nil, nil, fragment)
      [collection] -> build_public(authority, collection, nil, fragment)
      [collection, rkey] -> build_public(authority, collection, rkey, fragment)
      _ -> {:error, :invalid_at_uri}
    end
  end

  defp build(:space, authority, segments, fragment) do
    case segments do
      [space_type, skey] ->
        build_space(authority, space_type, skey, nil, nil, nil, fragment)

      [space_type, skey, author, collection, rkey] ->
        build_space(authority, space_type, skey, author, collection, rkey, fragment)

      _ ->
        {:error, :invalid_at_uri}
    end
  end

  defp build_public(authority, collection, rkey, fragment) do
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

  # The record segments arrive all-or-none from parse/1; the nil-defaults
  # clauses keep validation total for hand-built structs routed through here.
  defp build_space(authority, space_type, skey, author, collection, rkey, fragment) do
    with :ok <- validate_space_did(authority),
         :ok <- validate_space_type(space_type),
         :ok <- validate_skey(skey),
         :ok <- maybe_validate_record(author, collection, rkey) do
      {:ok,
       %__MODULE__{
         authority: authority,
         collection: collection,
         rkey: rkey,
         fragment: fragment,
         space_type: space_type,
         skey: skey,
         author: author
       }}
    end
  end

  defp maybe_validate_record(nil, nil, nil), do: :ok

  defp maybe_validate_record(author, collection, rkey) do
    with :ok <- validate_author(author),
         :ok <- validate_collection(collection) do
      validate_rkey(collection, rkey)
    end
  end

  defp validate_authority(authority) do
    if DID.valid?(authority) or Handle.valid?(authority) do
      :ok
    else
      {:error, :invalid_authority}
    end
  end

  # A space authority is always a DID: space identity and membership are keyed
  # on DIDs, so handles are not accepted in the space grammar.
  defp validate_space_did(did) do
    if DID.valid?(did), do: :ok, else: {:error, :invalid_authority}
  end

  defp validate_space_type(space_type) do
    if NSID.valid?(space_type), do: :ok, else: {:error, :invalid_space_type}
  end

  # An skey carries the same syntax requirements as a record key.
  defp validate_skey(skey) do
    if RecordKey.valid?(skey), do: :ok, else: {:error, :invalid_skey}
  end

  defp validate_author(author) do
    if DID.valid?(author), do: :ok, else: {:error, :invalid_author}
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
