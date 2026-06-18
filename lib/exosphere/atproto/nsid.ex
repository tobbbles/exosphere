defmodule Exosphere.ATProto.NSID do
  @moduledoc """
  Namespaced Identifiers (NSIDs).

  NSIDs name Lexicon schemas (and thus record collections / XRPC methods), for
  example `app.bsky.feed.post` or `com.atproto.repo.getRecord`.

  Syntax rules (see [the NSID spec](https://atproto.com/specs/nsid)):

  - At least 3 segments, max total length 317 characters.
  - The domain authority segments (all but the last) are each 1-63 characters of
    `[a-zA-Z0-9-]`, not starting or ending with a hyphen. The first segment (the
    TLD) must not start with a digit.
  - The final segment (the *name*) is 1-63 characters of `[a-zA-Z0-9]` only (no
    hyphens) and must not start with a digit.

  ## Examples

      iex> Exosphere.ATProto.NSID.valid?("app.bsky.feed.post")
      true

      iex> Exosphere.ATProto.NSID.parse("app.bsky.feed.post")
      {:ok, %{authority: "app.bsky.feed", name: "post", segments: ["app", "bsky", "feed", "post"]}}
  """

  @max_length 317

  # Reference regex from the spec.
  @nsid_regex ~r/^[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+(\.[a-zA-Z]([a-zA-Z0-9]{0,62})?)$/

  @type parsed :: %{authority: String.t(), name: String.t(), segments: [String.t()]}

  @doc """
  Validate an NSID string.
  """
  @spec valid?(String.t()) :: boolean()
  def valid?(nsid) when is_binary(nsid) do
    byte_size(nsid) <= @max_length and Regex.match?(@nsid_regex, nsid)
  end

  def valid?(_), do: false

  @doc """
  Parse an NSID into its authority, name, and segments.

  Returns `{:error, :invalid_nsid}` if the string is not a valid NSID.
  """
  @spec parse(String.t()) :: {:ok, parsed()} | {:error, :invalid_nsid}
  def parse(nsid) when is_binary(nsid) do
    if valid?(nsid) do
      segments = String.split(nsid, ".")
      {authority_segments, [name]} = Enum.split(segments, -1)

      {:ok,
       %{
         authority: Enum.join(authority_segments, "."),
         name: name,
         segments: segments
       }}
    else
      {:error, :invalid_nsid}
    end
  end

  def parse(_), do: {:error, :invalid_nsid}
end
