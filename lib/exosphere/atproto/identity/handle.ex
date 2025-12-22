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

  require Logger

  @type resolve_opts :: [timeout: pos_integer(), methods: [:dns | :https]]

  @doc """
  Resolve a handle to its DID.

  Tries DNS TXT record first, then falls back to HTTPS well-known endpoint.

  ## Options

  - `:timeout` - Request timeout in milliseconds (default: 10_000)
  - `:methods` - Resolution methods to try (default: [:dns, :https])
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

  Queries `_atproto.<handle>` for a TXT record containing the DID.
  """
  @spec resolve_dns(String.t()) :: {:ok, String.t()} | {:error, term()}
  def resolve_dns(handle) do
    query = ~c"_atproto.#{handle}"
    Logger.info("Resolving DNS TXT record for #{query}")

    case :inet_res.lookup(query, :in, :txt) do
      [] ->
        Logger.error("No DNS TXT record found for #{query}")
        {:error, :no_txt_record}

      records ->
        # Find a record that looks like a DID
        records
        |> Enum.flat_map(& &1)
        |> Enum.map(&to_string/1)
        |> Enum.find(&String.starts_with?(&1, "did="))
        |> case do
          "did=" <> did ->
            Logger.info("Found DID in DNS TXT record: #{did}")
            {:ok, did}

          nil ->
            {:error, :no_did_in_record}
        end
    end
  rescue
    _ -> {:error, :dns_lookup_failed}
  end

  @doc """
  Resolve a handle via HTTPS well-known endpoint.

  Fetches `https://<handle>/.well-known/atproto-did`.
  """
  @spec resolve_https(String.t(), resolve_opts()) :: {:ok, String.t()} | {:error, term()}
  def resolve_https(handle, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 10_000)
    url = "https://#{handle}/.well-known/atproto-did"

    case HTTP.get(url, timeout: timeout) do
      {:ok, %{status: 200, body: body}} ->
        # Body could be binary (plain text) or string (JSON decoded)
        did =
          case body do
            b when is_binary(b) -> String.trim(b)
            # Some servers might return JSON like {"did": "did:plc:..."}
            %{"did" => d} when is_binary(d) -> String.trim(d)
            _ -> nil
          end

        if did && String.starts_with?(did, "did:") do
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
    handle
    |> String.split(".")
    |> Enum.all?(fn label ->
      byte_size(label) >= 1 and
        byte_size(label) <= 63 and
        Regex.match?(~r/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/, label)
    end)
  end

  @doc """
  Normalize a handle to lowercase.
  """
  @spec normalize(String.t()) :: String.t()
  def normalize(handle) when is_binary(handle) do
    String.downcase(handle)
  end
end
