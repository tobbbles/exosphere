defmodule Exosphere.ATProto.OAuth.ServerMetadata do
  @moduledoc """
  Authorization Server and Resource Server metadata (RFC 8414 + the
  OAuth-Protected-Response draft used by ATProto).

  ATProto authorization servers publish their capabilities at
  `/.well-known/oauth-authorization-server`, and PDSs (as resource servers)
  publish their authorization server at
  `/.well-known/oauth-protected-resource`. Both documents are validated
  strictly against the ATProto OAuth profile before use: the `issuer` must
  match the origin the document was fetched from, and the declared features
  (PAR, PKCE, DPoP/ES256, `private_key_jwt`, the `atproto` scope, the
  authorization-response `iss` parameter) must all be supported.
  """

  alias Exosphere.ATProto.HTTP
  alias Exosphere.ATProto.OAuth.DPoP

  defstruct [
    :issuer,
    :authorization_endpoint,
    :token_endpoint,
    :pushed_authorization_request_endpoint,
    :scopes_supported,
    :raw
  ]

  @type t :: %__MODULE__{
          issuer: String.t(),
          authorization_endpoint: String.t(),
          token_endpoint: String.t(),
          pushed_authorization_request_endpoint: String.t(),
          scopes_supported: [String.t()],
          raw: map()
        }

  @authorization_server_well_known "/.well-known/oauth-authorization-server"
  @protected_resource_well_known "/.well-known/oauth-protected-resource"

  @doc """
  Fetch and validate the Authorization Server metadata document for a server
  origin.

  `origin` is the server's `scheme://host[:port]` root (e.g.
  `"https://bsky.social"`). The document's `issuer` must equal this origin.
  """
  @spec fetch(String.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def fetch(origin, opts \\ []) do
    http = Keyword.get(opts, :http, HTTP)

    with {:ok, %{status: 200, body: body}} when is_map(body) <-
           http.get(
             origin <> @authorization_server_well_known,
             request_opts(opts)
           ),
         {:ok, metadata} <- validate(body, origin) do
      {:ok, metadata}
    else
      {:ok, %{status: status}} -> {:error, {:as_metadata_fetch_failed, status}}
      {:error, _} = error -> error
      _ -> {:error, :invalid_as_metadata}
    end
  end

  @doc """
  Validate a parsed Authorization Server metadata document against the
  ATProto OAuth profile requirements.
  """
  @spec validate(map(), String.t()) :: {:ok, t()} | {:error, term()}
  def validate(body, origin) when is_map(body) and is_binary(origin) do
    with :ok <- check_issuer(body, origin) do
      struct_from(body)
    end
  end

  @doc """
  Fetch a PDS's Resource Server metadata
  (`/.well-known/oauth-protected-resource`) and return the authorization
  server origin it declares.

  Per the spec the list must contain exactly one origin URL. Returns
  `{:error, :protected_resource_metadata_not_found}` when the PDS hosts its
  own authorization server (HTTP 404).
  """
  @spec fetch_authorization_server(String.t(), keyword()) ::
          {:ok, String.t()} | {:error, term()}
  def fetch_authorization_server(pds_origin, opts \\ []) do
    http = Keyword.get(opts, :http, HTTP)

    with {:ok, %{status: 200, body: %{"authorization_servers" => servers}}}
         when is_list(servers) <-
           http.get(
             pds_origin <> @protected_resource_well_known,
             request_opts(opts)
           ),
         {:ok, origin} <- single_origin(servers) do
      {:ok, origin}
    else
      {:ok, %{status: 404}} -> {:error, :protected_resource_metadata_not_found}
      {:ok, %{status: status}} -> {:error, {:protected_resource_fetch_failed, status}}
      {:error, _} = error -> error
      _ -> {:error, :invalid_protected_resource_metadata}
    end
  end

  @doc """
  The scopes to request: the intersection of the client's desired scopes
  with those the server supports.
  """
  @spec supported_scopes(t(), [String.t()]) :: [String.t()]
  def supported_scopes(%__MODULE__{scopes_supported: supported}, desired)
      when is_list(desired) do
    Enum.filter(desired, &(&1 in supported))
  end

  @doc """
  The metadata as a plain, `Jason`-encodable map for persistence. The `raw`
  document is dropped — the validated fields are what clients rely on.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = metadata) do
    metadata
    |> Map.from_struct()
    |> Map.delete(:raw)
  end

  @doc """
  Rebuild metadata serialized with `to_map/1`.
  """
  @spec from_map(map()) :: {:ok, t()} | {:error, :invalid_server_metadata}
  def from_map(map) when is_map(map) do
    fields = Map.new(map, fn {k, v} -> {String.to_atom(k), v} end)
    {:ok, struct!(__MODULE__, Map.put(fields, :raw, %{}))}
  rescue
    _ -> {:error, :invalid_server_metadata}
  end

  def from_map(_), do: {:error, :invalid_server_metadata}

  defp check_issuer(%{"issuer" => issuer}, origin) do
    if DPoP.origin(issuer) == DPoP.origin(origin) and issuer == DPoP.origin(issuer) do
      :ok
    else
      {:error, :issuer_mismatch}
    end
  end

  defp check_issuer(_, _), do: {:error, {:invalid_server_metadata, :issuer_required}}

  defp struct_from(body) do
    required_urls = [
      authorization_endpoint: "authorization_endpoint",
      token_endpoint: "token_endpoint",
      pushed_authorization_request_endpoint: "pushed_authorization_request_endpoint"
    ]

    with {:ok, urls} <- fetch_urls(body, required_urls),
         :ok <- check_string_arrays(body),
         :ok <- check_flags(body) do
      {:ok,
       %__MODULE__{
         issuer: body["issuer"],
         authorization_endpoint: urls[:authorization_endpoint],
         token_endpoint: urls[:token_endpoint],
         pushed_authorization_request_endpoint: urls[:pushed_authorization_request_endpoint],
         scopes_supported: body["scopes_supported"] || [],
         raw: body
       }}
    end
  end

  defp fetch_urls(body, required) do
    Enum.reduce_while(required, {:ok, []}, fn {key, field}, {:ok, acc} ->
      case body[field] do
        url when is_binary(url) ->
          if same_origin?(url, body["issuer"]) do
            {:cont, {:ok, Keyword.put(acc, key, url)}}
          else
            {:halt, {:error, {:invalid_server_metadata, {:not_issuer_origin, field}}}}
          end

        _ ->
          {:halt, {:error, {:invalid_server_metadata, {:missing, field}}}}
      end
    end)
  end

  defp check_string_arrays(body) do
    checks = [
      {"response_types_supported", ["code"]},
      {"grant_types_supported", ["authorization_code", "refresh_token"]},
      {"scopes_supported", ["atproto"]},
      {"token_endpoint_auth_methods_supported", ["none", "private_key_jwt"]},
      {"token_endpoint_auth_signing_alg_values_supported", ["ES256"]},
      {"dpop_signing_alg_values_supported", ["ES256"]}
    ]

    Enum.reduce_while(checks, :ok, fn {field, must_include}, :ok ->
      case body[field] do
        values when is_list(values) ->
          if Enum.all?(must_include, &(&1 in values)) do
            {:cont, :ok}
          else
            {:halt, {:error, {:invalid_server_metadata, {:missing_supported, field}}}}
          end

        _ ->
          {:halt, {:error, {:invalid_server_metadata, {:missing, field}}}}
      end
    end)
  end

  defp check_flags(body) do
    flags = [
      {"require_pushed_authorization_requests", true},
      {"client_id_metadata_document_supported", true},
      {"authorization_response_iss_parameter_supported", true}
    ]

    Enum.reduce_while(flags, :ok, fn {field, expected}, :ok ->
      if body[field] == expected do
        {:cont, :ok}
      else
        {:halt, {:error, {:invalid_server_metadata, {:flag_not_set, field}}}}
      end
    end)
  end

  defp single_origin([origin]) when is_binary(origin), do: {:ok, DPoP.origin(origin)}
  defp single_origin(_), do: {:error, :multiple_authorization_servers}

  defp request_opts(opts) do
    case Keyword.get(opts, :timeout) do
      nil -> [follow_redirects: false]
      timeout -> [follow_redirects: false, timeout: timeout]
    end
  end

  defp same_origin?(url, issuer) do
    DPoP.origin(url) == DPoP.origin(issuer)
  end
end
