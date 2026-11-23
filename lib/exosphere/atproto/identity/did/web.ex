defmodule Exosphere.ATProto.Identity.DID.Web do
  @moduledoc """
  DID:Web resolution.

  DID:Web is a W3C standard that resolves DIDs via HTTPS.
  The DID Document is fetched from `https://<domain>/.well-known/did.json`.

  ## Examples

      iex> Exosphere.ATProto.Identity.DID.Web.resolve("did:web:example.com")
      {:ok, %Document{...}}

  ## Notes

  - Only hostname-level DIDs are supported (no paths)
  - Port numbers are only allowed for localhost in development
  """

  alias Exosphere.ATProto.HTTP
  alias Exosphere.ATProto.Identity.Document

  @type resolve_opts :: [timeout: pos_integer(), http_client: module()]

  @doc """
  Resolve a did:web to its DID Document.

  ## Options

  - `:timeout` - HTTP request timeout in milliseconds (default: 10_000)
  - `:http_client` - HTTP client module implementing `HTTP.Behaviour`
    (default: `Exosphere.ATProto.HTTP`; useful for testing)
  """
  @spec resolve(String.t(), resolve_opts()) :: {:ok, Document.t()} | {:error, term()}
  def resolve("did:web:" <> host = did, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 10_000)
    http = Keyword.get(opts, :http_client, HTTP)

    with {:ok, url} <- build_url(host) do
      case http.get(url, timeout: timeout) do
        {:ok, %{status: 200, body: body}} when is_map(body) ->
          Document.parse(body, did)

        {:ok, %{status: 200, body: body}} when is_binary(body) ->
          case Jason.decode(body) do
            {:ok, parsed} when is_map(parsed) -> Document.parse(parsed, did)
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

  @hostname ~r/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\z/

  @doc """
  Whether the method-specific part of a `did:web` (still percent-encoded)
  is one atproto accepts: a lowercase hostname, no path, no port — except
  `localhost%3A<port>` for development. Any other `:` (raw or encoded) is
  refused, so `did:web:example.com:user` (a W3C path DID) never turns into
  a request to `https://example.com:user/`.
  """
  @spec valid_host?(String.t()) :: boolean()
  def valid_host?(host) when is_binary(host) do
    case String.split(host, "%3A") do
      [hostname] -> hostname?(hostname)
      ["localhost", port] -> Regex.match?(~r/\A[0-9]{1,5}\z/, port)
      _ -> false
    end
  end

  def valid_host?(_), do: false

  defp hostname?(hostname) do
    byte_size(hostname) <= 253 and Regex.match?(@hostname, hostname)
  end

  defp build_url(host) do
    cond do
      String.contains?(URI.decode(host), "/") ->
        {:error, :path_not_allowed}

      not valid_host?(host) ->
        {:error, :invalid_did_format}

      true ->
        case String.split(host, "%3A") do
          ["localhost", port] ->
            {:ok, "http://localhost:#{port}/.well-known/did.json"}

          [hostname] when hostname in ["localhost", "127.0.0.1"] ->
            {:ok, "http://#{hostname}/.well-known/did.json"}

          [hostname] ->
            {:ok, "https://#{hostname}/.well-known/did.json"}
        end
    end
  end
end
