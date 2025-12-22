defmodule Exosphere.ATProto.Identity.DID.PLC do
  @moduledoc """
  DID:PLC resolution.

  DID:PLC is Bluesky's novel DID method with key rotation and recovery support.
  DIDs are resolved via the PLC directory at `https://plc.directory`.

  ## Examples

      iex> Exosphere.ATProto.Identity.DID.PLC.resolve("did:plc:z72i7hdynmk6r22z27h6tvur")
      {:ok, %Document{...}}
  """

  alias Exosphere.ATProto.HTTP
  alias Exosphere.ATProto.Identity.Document

  require Logger

  @plc_directory "https://plc.directory"

  @type resolve_opts :: [timeout: pos_integer(), plc_directory: String.t()]

  @doc """
  Resolve a did:plc to its DID Document.

  ## Options

  - `:timeout` - HTTP request timeout in milliseconds (default: 10_000)
  - `:plc_directory` - PLC directory URL (default: "https://plc.directory")
  """
  @spec resolve(String.t(), resolve_opts()) :: {:ok, Document.t()} | {:error, term()}
  def resolve("did:plc:" <> _ = did, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 10_000)
    directory = Keyword.get(opts, :plc_directory, @plc_directory)
    url = "#{directory}/#{did}"

    Logger.debug("[DID.PLC] Resolving DID document from: #{url}")

    case HTTP.get(url, timeout: timeout) do
      {:ok, %{status: 200, body: body}} when is_map(body) ->
        Logger.debug("[DID.PLC] Received DID document for #{did}")
        Document.parse(body)

      {:ok, %{status: 200, body: body}} when is_binary(body) ->
        # Body wasn't decoded as JSON - try to parse it manually
        Logger.debug("[DID.PLC] Body is binary, attempting JSON decode")

        case Jason.decode(body) do
          {:ok, parsed} when is_map(parsed) ->
            Document.parse(parsed)

          {:ok, _other} ->
            Logger.error("[DID.PLC] Decoded JSON is not a map: #{inspect(body, limit: 200)}")
            {:error, {:invalid_response, :not_a_map}}

          {:error, decode_error} ->
            Logger.error("[DID.PLC] Failed to decode JSON: #{inspect(decode_error)}")
            {:error, {:invalid_response, :json_decode_failed}}
        end

      {:ok, %{status: 200, body: body}} ->
        Logger.error("[DID.PLC] Unexpected body type for #{did}: #{inspect(body, limit: 200)}")

        {:error, {:invalid_response, :unexpected_body_type}}

      {:ok, %{status: 404}} ->
        Logger.debug("[DID.PLC] DID not found: #{did}")
        {:error, :not_found}

      {:ok, %{status: status, body: body}} ->
        Logger.error("[DID.PLC] HTTP #{status} for #{did}: #{inspect(body, limit: 200)}")
        {:error, {:http_error, status}}

      {:error, reason} ->
        Logger.error("[DID.PLC] Request failed for #{did}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Get the audit log for a did:plc.

  Returns the full history of operations for the DID.
  """
  @spec get_audit_log(String.t(), resolve_opts()) :: {:ok, list(map())} | {:error, term()}
  def get_audit_log("did:plc:" <> _ = did, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 10_000)
    directory = Keyword.get(opts, :plc_directory, @plc_directory)
    url = "#{directory}/#{did}/log/audit"

    case HTTP.get(url, timeout: timeout) do
      {:ok, %{status: 200, body: body}} when is_list(body) ->
        {:ok, body}

      {:ok, %{status: 200, body: body}} when is_binary(body) ->
        case Jason.decode(body) do
          {:ok, parsed} when is_list(parsed) -> {:ok, parsed}
          _ -> {:error, {:invalid_response, :not_a_list}}
        end

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Get the current PLC data (internal representation) for a did:plc.

  This returns the PLC-specific data format, not the DID Document.
  """
  @spec get_data(String.t(), resolve_opts()) :: {:ok, map()} | {:error, term()}
  def get_data("did:plc:" <> _ = did, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 10_000)
    directory = Keyword.get(opts, :plc_directory, @plc_directory)
    url = "#{directory}/#{did}/data"

    case HTTP.get(url, timeout: timeout) do
      {:ok, %{status: 200, body: body}} when is_map(body) ->
        {:ok, body}

      {:ok, %{status: 200, body: body}} when is_binary(body) ->
        case Jason.decode(body) do
          {:ok, parsed} when is_map(parsed) -> {:ok, parsed}
          _ -> {:error, {:invalid_response, :not_a_map}}
        end

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
