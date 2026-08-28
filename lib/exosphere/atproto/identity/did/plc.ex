defmodule Exosphere.ATProto.Identity.DID.PLC do
  @moduledoc """
  DID:PLC resolution and operation submission.

  DID:PLC is Bluesky's novel DID method with key rotation and recovery support.
  DIDs are resolved via the PLC directory at `https://plc.directory`.

  Reads live here; the write side is split across three modules:

  - `Exosphere.ATProto.Identity.DID.PLC.Operation` — build and validate operations
  - `Exosphere.ATProto.Identity.DID.PLC.Signer` — sign, verify, derive the DID
  - `Exosphere.ATProto.Identity.DID.PLC.AuditLog` — validate a whole operation log

  ## Examples

      iex> Exosphere.ATProto.Identity.DID.PLC.resolve("did:plc:z72i7hdynmk6r22z27h6tvur")
      {:ok, %Document{...}}

  Creating an identity — the DID falls out of the signed genesis operation
  rather than being allocated:

      {:ok, op} = Operation.new(rotation_keys: [key], also_known_as: ["at://alice.example.com"])
      {:ok, signed} = Signer.sign(op, private_key, :secp256k1)
      {:ok, did} = Signer.derive_did(signed)
      {:ok, ^did} = PLC.submit(did, signed)
  """

  alias Exosphere.ATProto.HTTP
  alias Exosphere.ATProto.Identity.DID.PLC.AuditLog
  alias Exosphere.ATProto.Identity.DID.PLC.Operation
  alias Exosphere.ATProto.Identity.Document

  require Logger

  @plc_directory "https://plc.directory"

  @type resolve_opts :: [
          timeout: pos_integer(),
          plc_directory: String.t(),
          http_client: module()
        ]

  @type submit_opts :: [
          timeout: pos_integer(),
          plc_directory: String.t(),
          http_client: module(),
          max_attempts: pos_integer(),
          backoff_ms: pos_integer()
        ]

  # The directory tightened the production limit to 4 KB (from the spec's
  # 7.5 KB); refusing locally beats a rejected round trip.
  @max_operation_bytes 4096

  @doc """
  Resolve a did:plc to its DID Document.

  ## Options

  - `:timeout` - HTTP request timeout in milliseconds (default: 10_000)
  - `:plc_directory` - PLC directory URL (default: "https://plc.directory")
  - `:http_client` - HTTP client module implementing `HTTP.Behaviour`
    (default: `Exosphere.ATProto.HTTP`; useful for testing)
  """
  @spec resolve(String.t(), resolve_opts()) :: {:ok, Document.t()} | {:error, term()}
  def resolve("did:plc:" <> _ = did, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 10_000)
    directory = Keyword.get(opts, :plc_directory, @plc_directory)
    http = Keyword.get(opts, :http_client, HTTP)
    url = "#{directory}/#{did}"

    Logger.debug("[DID.PLC] Resolving DID document from: #{url}")

    case http.get(url, timeout: timeout) do
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
    http = Keyword.get(opts, :http_client, HTTP)
    url = "#{directory}/#{did}/log/audit"

    case http.get(url, timeout: timeout) do
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
    http = Keyword.get(opts, :http_client, HTTP)
    url = "#{directory}/#{did}/data"

    case http.get(url, timeout: timeout) do
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

  @doc """
  Submit a signed operation to the directory (`POST /:did`).

  Retries on transport failures and 5xx responses with linear backoff. A 4xx
  is **not** retried — the directory has judged the operation invalid, and
  resending it unchanged cannot help.

  Submission is idempotent at the directory: resubmitting an operation the
  directory already holds is accepted rather than duplicated, so a retry
  after an ambiguous timeout is safe.

  ## Options

  - `:max_attempts` - total attempts including the first (default: 3)
  - `:backoff_ms` - base backoff, multiplied by attempt number (default: 500)
  - `:timeout`, `:plc_directory`, `:http_client` - as `resolve/2`
  """
  @spec submit(String.t(), Operation.t(), submit_opts()) ::
          {:ok, String.t()} | {:error, term()}
  def submit("did:plc:" <> _ = did, op, opts \\ []) when is_map(op) do
    with :ok <- Operation.validate(op),
         :ok <- check_size(op) do
      do_submit(did, op, opts, 1)
    end
  end

  defp do_submit(did, op, opts, attempt) do
    timeout = Keyword.get(opts, :timeout, 10_000)
    directory = Keyword.get(opts, :plc_directory, @plc_directory)
    http = Keyword.get(opts, :http_client, HTTP)
    max_attempts = Keyword.get(opts, :max_attempts, 3)
    backoff = Keyword.get(opts, :backoff_ms, 500)
    url = "#{directory}/#{did}"

    Logger.debug("[DID.PLC] Submitting operation for #{did} (attempt #{attempt})")

    case http.post(url, json: op, timeout: timeout) do
      {:ok, %{status: status}} when status in 200..299 ->
        Logger.debug("[DID.PLC] Operation accepted for #{did}")
        {:ok, did}

      {:ok, %{status: status, body: body}} when status in 400..499 ->
        Logger.error("[DID.PLC] Operation rejected for #{did}: #{inspect(body, limit: 200)}")
        {:error, {:rejected, status, body}}

      {:ok, %{status: status}} when attempt < max_attempts ->
        Logger.warning("[DID.PLC] HTTP #{status} for #{did}, retrying")
        Process.sleep(backoff * attempt)
        do_submit(did, op, opts, attempt + 1)

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} when attempt < max_attempts ->
        Logger.warning("[DID.PLC] Submit failed for #{did}: #{inspect(reason)}, retrying")
        Process.sleep(backoff * attempt)
        do_submit(did, op, opts, attempt + 1)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  The CID of the current head of a DID's operation log.

  This is what a new operation's `prev` must point at. Fetch it rather than
  reusing a locally cached value: an operation chained from a stale head is
  a fork, not an update, and the directory will judge it as one.
  """
  @spec head(String.t(), resolve_opts()) :: {:ok, String.t()} | {:error, term()}
  def head("did:plc:" <> _ = did, opts \\ []) do
    case get_audit_log(did, opts) do
      {:ok, entries} ->
        entries
        |> Enum.reject(&Map.get(&1, "nullified", false))
        |> List.last()
        |> case do
          nil -> {:error, :empty_log}
          %{"cid" => cid} -> {:ok, cid}
          _ -> {:error, {:invalid_response, :missing_cid}}
        end

      error ->
        error
    end
  end

  @doc """
  Fetch and validate a DID's full audit log.

  Verifies every signature, the chain, nullification and the 72-hour recovery
  window, and cross-checks the computed nullification against the flags the
  directory reported.
  """
  @spec verify_audit_log(String.t(), resolve_opts()) :: :ok | {:error, term()}
  def verify_audit_log("did:plc:" <> _ = did, opts \\ []) do
    case get_audit_log(did, opts) do
      {:ok, entries} -> AuditLog.validate_against_flags(entries)
      error -> error
    end
  end

  defp check_size(op) do
    case Operation.signed_bytes(op) do
      {:ok, bytes} when byte_size(bytes) > @max_operation_bytes ->
        {:error, {:operation_too_large, byte_size(bytes)}}

      {:ok, _} ->
        :ok

      error ->
        error
    end
  end
end
