defmodule Exosphere.ATProto.Identity.Handle do
  @moduledoc """
  Handle resolution for Exosphere.ATProto.

  Handles are DNS domain names that resolve to DIDs. Resolution can occur via:

  1. DNS TXT record at `_atproto.<handle>`
  2. HTTPS well-known endpoint at `https://<handle>/.well-known/atproto-did`

  ## Examples

      # Resolve a handle to its DID
      {:ok, did} = Exosphere.ATProto.Identity.Handle.resolve("alice.bsky.social")
      # => {:ok, "did:plc:z72i7hdynmk6r22z27h6tvur"}

      # Validate handle syntax
      Exosphere.ATProto.Identity.Handle.valid?("alice.example.com")
      # => true
  """

  alias Exosphere.ATProto.HTTP
  alias Exosphere.ATProto.Identity.DID

  require Logger

  @type resolve_opts :: [
          timeout: pos_integer(),
          methods: [:dns | :https],
          http_client: module()
        ]

  @doc """
  Resolve a handle to its DID.

  Tries DNS TXT record first, then falls back to HTTPS well-known endpoint.

  ## Options

  - `:timeout` - Request timeout in milliseconds (default: 10_000)
  - `:methods` - Resolution methods to try (default: `[:dns, :https]`)
  - `:http_client` - HTTP client module implementing `HTTP.Behaviour`
    (default: `Exosphere.ATProto.HTTP`; useful for testing)
  """
  @spec resolve(String.t(), resolve_opts()) :: {:ok, String.t()} | {:error, term()}
  def resolve(handle, opts \\ []) when is_binary(handle) do
    methods = Keyword.get(opts, :methods, [:dns, :https])
    Logger.debug("[Handle] Resolving handle: #{handle} using methods: #{inspect(methods)}")

    result =
      Enum.reduce_while(methods, {:error, :not_found}, fn method, _acc ->
        case resolve_with_method(handle, method, opts) do
          {:ok, did} ->
            Logger.debug("[Handle] Successfully resolved #{handle} via #{method}: #{did}")
            {:halt, {:ok, did}}

          {:error, reason} ->
            Logger.debug("[Handle] Method #{method} failed for #{handle}: #{inspect(reason)}")
            {:cont, {:error, :not_found}}
        end
      end)

    case result do
      {:ok, _} = success ->
        success

      {:error, :not_found} ->
        Logger.warning("[Handle] Failed to resolve handle: #{handle}")
        {:error, :not_found}
    end
  end

  defp resolve_with_method(handle, :dns, _opts) do
    resolve_dns(handle)
  end

  defp resolve_with_method(handle, :https, opts) do
    resolve_https(handle, opts)
  end

  @doc """
  Resolve a handle via DNS TXT record.

  Queries `_atproto.<handle>` for a TXT record containing the DID; see
  `parse_txt_records/1` for how the answer is judged.
  """
  @spec resolve_dns(String.t()) :: {:ok, String.t()} | {:error, term()}
  def resolve_dns(handle) do
    query = ~c"_atproto.#{handle}"
    Logger.debug("Resolving DNS TXT record for #{query}")

    case :inet_res.lookup(query, :in, :txt) do
      [] ->
        Logger.debug("No DNS TXT record found for #{query}")
        {:error, :no_txt_record}

      records ->
        parse_txt_records(records)
    end
  rescue
    _ -> {:error, :dns_lookup_failed}
  end

  @doc """
  Pick the DID out of the `_atproto` TXT records of a handle, as
  `:inet_res.lookup/3` returns them (each record a list of character-string
  chunks, which are concatenated).

  Per the handle spec: records not starting with `did=` are ignored; "only
  a single valid record should exist … If multiple valid records with
  different DIDs are present, resolution should fail"
  (`{:error, :multiple_dids}`). The DID itself must be a strictly valid
  atproto DID (`DID.atproto_valid?/1`), otherwise `{:error, :invalid_did}`.
  No `did=` record at all is `{:error, :no_did_in_record}`.
  """
  @spec parse_txt_records([[charlist() | String.t()]]) :: {:ok, String.t()} | {:error, term()}
  def parse_txt_records(records) when is_list(records) do
    records
    |> Enum.map(fn chunks -> chunks |> List.wrap() |> Enum.map_join("", &to_string/1) end)
    |> Enum.flat_map(fn
      "did=" <> did -> [did]
      _ -> []
    end)
    |> Enum.uniq()
    |> case do
      [] -> {:error, :no_did_in_record}
      [did] -> check_did(did)
      _many -> {:error, :multiple_dids}
    end
  end

  defp check_did(did) do
    if DID.atproto_valid?(did), do: {:ok, did}, else: {:error, :invalid_did}
  end

  @doc """
  Resolve a handle via HTTPS well-known endpoint.

  Fetches `https://<handle>/.well-known/atproto-did`.
  """
  @spec resolve_https(String.t(), resolve_opts()) :: {:ok, String.t()} | {:error, term()}
  def resolve_https(handle, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 10_000)
    http = Keyword.get(opts, :http_client, HTTP)
    url = "https://#{handle}/.well-known/atproto-did"

    case http.get(url, timeout: timeout) do
      {:ok, %{status: 200, body: body}} ->
        # Body could be binary (plain text) or string (JSON decoded)
        did =
          case body do
            b when is_binary(b) -> String.trim(b)
            # Some servers might return JSON like {"did": "did:plc:..."}
            %{"did" => d} when is_binary(d) -> String.trim(d)
            _ -> nil
          end

        if is_binary(did) and DID.atproto_valid?(did) do
          {:ok, did}
        else
          {:error, :invalid_response}
        end

      {:ok, %{status: status}} when status in 300..399 ->
        {:error, :redirect_not_followed}

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Validate handle syntax.

  Handles must be valid domain names with:
  - At least one dot
  - Only allowed characters (letters, digits, hyphens, dots)
  - No consecutive dots or leading/trailing dots
  - Labels between 1-63 characters
  - Total length under 253 characters
  - A final segment (the TLD) that does not start with a digit
  """
  @spec valid?(String.t()) :: boolean()
  def valid?(handle) when is_binary(handle) do
    # Basic structural checks
    cond do
      String.length(handle) > 253 -> false
      not String.contains?(handle, ".") -> false
      String.starts_with?(handle, ".") -> false
      String.ends_with?(handle, ".") -> false
      String.contains?(handle, "..") -> false
      true -> valid_labels?(handle)
    end
  end

  def valid?(_), do: false

  defp valid_labels?(handle) do
    labels = String.split(handle, ".")

    Enum.all?(labels, fn label ->
      byte_size(label) >= 1 and
        byte_size(label) <= 63 and
        Regex.match?(~r/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/, label)
    end) and valid_tld?(List.last(labels))
  end

  # The last segment (the "top level domain") must not start with a digit.
  defp valid_tld?(tld), do: Regex.match?(~r/^[a-zA-Z]/, tld)

  @doc """
  Normalize a handle to lowercase.
  """
  @spec normalize(String.t()) :: String.t()
  def normalize(handle) when is_binary(handle) do
    String.downcase(handle)
  end
end
