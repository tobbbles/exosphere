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
  def resolve("did:web:" <> domain, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 10_000)
    http = Keyword.get(opts, :http_client, HTTP)

    with {:ok, url} <- build_url(domain) do
      case http.get(url, timeout: timeout) do
        {:ok, %{status: 200, body: body}} when is_map(body) ->
          Document.parse(body)

        {:ok, %{status: 404}} ->
          {:error, :not_found}

        {:ok, %{status: status}} ->
          {:error, {:http_error, status}}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp build_url(domain) do
    # Decode percent-encoded characters (e.g., %3A for :)
    decoded = URI.decode(domain)

    # Check for path components (not allowed in Exosphere.ATProto)
    if String.contains?(decoded, "/") do
      {:error, :path_not_allowed}
    else
      # Handle port numbers (only for localhost)
      {host, port} = parse_host_port(decoded)

      scheme =
        if host in ["localhost", "127.0.0.1"] do
          "http"
        else
          "https"
        end

      url =
        if port do
          "#{scheme}://#{host}:#{port}/.well-known/did.json"
        else
          "#{scheme}://#{host}/.well-known/did.json"
        end

      {:ok, url}
    end
  end

  defp parse_host_port(domain) do
    case String.split(domain, ":") do
      [host] -> {host, nil}
      [host, port] -> {host, port}
      _ -> {domain, nil}
    end
  end
end
