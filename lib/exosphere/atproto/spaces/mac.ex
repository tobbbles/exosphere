defmodule Exosphere.ATProto.Spaces.Mac do
  @moduledoc """
  Commit and record MACs, and the headers that carry them (proposal 0016,
  "Authenticity headers", "Commit MAC", "Record MAC"; atproto `5791385`).

  Space repos carry no signatures: a repo host authenticates what it serves
  with an HMAC-SHA256 keyed by a per-request shared secret (`Spaces.Kem`),
  so a leaked response proves nothing to a third party. The MAC travels in
  an HTTP header, never in the repo data.

      context = "atproto-space-repo-v1"
         || uint16be(len(space)) || space
         || uint16be(len(repo))  || repo
         || uint16be(len(rev))   || rev
      commit_mac = HMAC-SHA256(shared_secret, context || data)

      context = "atproto-space-record-v1" || uint16be(len(uri)) || uri
      record_mac = HMAC-SHA256(shared_secret, context || record_cid_bytes)

  String fields are UTF-8 with big-endian `uint16` length prefixes.

  The syncer asks for a MAC with `Atproto-Space-Want-Mac` (an RFC 9651
  Dictionary, `type="atproto-space-repo", ver=1, key_share="did:key:…"`) and
  the host answers in `Atproto-Space-Mac`
  (`type="atproto-space-repo", ver=1, mac=:…:`), listing the request header
  in `Vary`. `getLatestCommit`, `listRepoOps` (when it returns a commit) and
  `getRepo` use the commit type; `getRecord` the record type.
  """

  alias Exosphere.ATProto.Spaces.StructuredFields, as: SF

  @commit_type "atproto-space-repo"
  @record_type "atproto-space-record"
  # Commits share their MAC version with the commit format version.
  @commit_version 1
  @record_version 1

  @want_mac_header "atproto-space-want-mac"
  @mac_header "atproto-space-mac"

  @type mac_type :: :commit | :record

  @doc "The request header name (lowercase)."
  @spec want_mac_header_name() :: String.t()
  def want_mac_header_name, do: @want_mac_header

  @doc "The response header name (lowercase)."
  @spec mac_header_name() :: String.t()
  def mac_header_name, do: @mac_header

  @doc """
  The commit MAC over a commit map (`"space"`, `"repo"`, `"rev"`, `"data"`).
  """
  @spec commit_mac(binary(), map()) :: <<_::256>>
  def commit_mac(shared_secret, %{"space" => space, "repo" => repo, "rev" => rev, "data" => data})
      when is_binary(data) do
    :crypto.mac(:hmac, :sha256, shared_secret, commit_context(space, repo, rev) <> data)
  end

  @doc "The domain-separated context the commit MAC covers ahead of `data`."
  @spec commit_context(String.t(), String.t(), String.t()) :: binary()
  def commit_context(space, repo, rev) do
    "#{@commit_type}-v#{@commit_version}" <>
      length_prefixed(space) <> length_prefixed(repo) <> length_prefixed(rev)
  end

  @doc "The record MAC over a record's full URI and its binary CID."
  @spec record_mac(binary(), String.t(), binary()) :: <<_::256>>
  def record_mac(shared_secret, uri, cid_bytes) when is_binary(cid_bytes) do
    context = "#{@record_type}-v#{@record_version}" <> length_prefixed(uri)
    :crypto.mac(:hmac, :sha256, shared_secret, context <> cid_bytes)
  end

  @doc "Constant-time MAC comparison."
  @spec equal?(binary(), binary()) :: boolean()
  def equal?(a, b) when is_binary(a) and is_binary(b),
    do: byte_size(a) == byte_size(b) and :crypto.hash_equals(a, b)

  def equal?(_, _), do: false

  @doc "The `Atproto-Space-Want-Mac` request header value."
  @spec want_mac_header(mac_type(), String.t()) :: String.t()
  def want_mac_header(type, key_share) do
    SF.serialize_dictionary([
      {"type", {type_name(type), []}},
      {"ver", {version(type), []}},
      {"key_share", {key_share, []}}
    ])
  end

  @doc "The `Atproto-Space-Mac` response header value."
  @spec mac_header(mac_type(), binary()) :: String.t()
  def mac_header(type, mac) do
    SF.serialize_dictionary([
      {"type", {type_name(type), []}},
      {"ver", {version(type), []}},
      {"mac", {{:bytes, mac}, []}}
    ])
  end

  @doc """
  Parse a request's `Atproto-Space-Want-Mac`, returning its `key_share`.
  Missing or malformed headers and unsupported types or versions are
  `{:error, {:bad_space_mac, reason}}` — the `BadSpaceMac` the host answers.
  """
  @spec parse_want_mac_header(String.t() | nil, mac_type()) ::
          {:ok, String.t()} | {:error, {:bad_space_mac, term()}}
  def parse_want_mac_header(value, type) do
    with {:ok, dict} <- parse(value, type) do
      case SF.get_bare(dict, "key_share") do
        key_share when is_binary(key_share) -> {:ok, key_share}
        _ -> {:error, {:bad_space_mac, :missing_key_share}}
      end
    end
  end

  @doc "Parse a response's `Atproto-Space-Mac`, returning the MAC bytes."
  @spec parse_mac_header(String.t() | nil, mac_type()) ::
          {:ok, binary()} | {:error, {:bad_space_mac, term()}}
  def parse_mac_header(value, type) do
    with {:ok, dict} <- parse(value, type) do
      case SF.get_bare(dict, "mac") do
        {:bytes, mac} -> {:ok, mac}
        _ -> {:error, {:bad_space_mac, :missing_mac}}
      end
    end
  end

  defp parse(value, type) when is_binary(value) do
    with {:ok, dict} <- SF.parse_dictionary(value),
         :ok <- no_inner_lists(dict) do
      cond do
        SF.get_bare(dict, "type") != type_name(type) ->
          {:error, {:bad_space_mac, :unsupported_type}}

        SF.get_bare(dict, "ver") != version(type) ->
          {:error, {:bad_space_mac, :unsupported_version}}

        true ->
          {:ok, dict}
      end
    else
      {:error, :invalid_structured_field} -> {:error, {:bad_space_mac, :malformed_header}}
      {:error, _} = error -> error
    end
  end

  defp parse(_value, _type), do: {:error, {:bad_space_mac, :missing_header}}

  defp no_inner_lists(dict) do
    if Enum.any?(dict, &match?({_, {:inner_list, _, _}}, &1)),
      do: {:error, {:bad_space_mac, :malformed_header}},
      else: :ok
  end

  defp type_name(:commit), do: @commit_type
  defp type_name(:record), do: @record_type
  defp version(:commit), do: @commit_version
  defp version(:record), do: @record_version

  defp length_prefixed(str) when is_binary(str) do
    if byte_size(str) > 0xFFFF, do: raise(ArgumentError, "MAC context field exceeds uint16")
    <<byte_size(str)::unsigned-big-16, str::binary>>
  end
end
