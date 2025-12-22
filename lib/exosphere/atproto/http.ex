defmodule Exosphere.ATProto.HTTP do
  @moduledoc """
  Simple HTTP client using Mint.

  Provides a high-level API for making HTTP requests using Mint under the hood.
  Each request opens a new connection (suitable for infrequent requests to
  many different hosts, as is common in Exosphere.ATProto).

  ## Examples

      {:ok, response} = Exosphere.ATProto.HTTP.get("https://plc.directory/did:plc:abc")
      {:ok, response} = Exosphere.ATProto.HTTP.post("https://pds.example.com/xrpc/...", json: %{})
  """

  require Logger

  @default_timeout 30_000

  @type response :: %{
          status: pos_integer(),
          headers: [{String.t(), String.t()}],
          body: binary()
        }

  @type request_opts :: [
          timeout: pos_integer(),
          headers: [{String.t(), String.t()}],
          json: map(),
          body: binary()
        ]

  @doc """
  Make an HTTP GET request.

  ## Options

  - `:timeout` - Request timeout in milliseconds (default: 30_000)
  - `:headers` - Additional headers to send
  """
  @spec get(String.t(), request_opts()) :: {:ok, response()} | {:error, term()}
  def get(url, opts \\ []) do
    request(:get, url, opts)
  end

  @doc """
  Make an HTTP POST request.

  ## Options

  - `:timeout` - Request timeout in milliseconds (default: 30_000)
  - `:headers` - Additional headers to send
  - `:json` - Map to encode as JSON body
  - `:body` - Raw binary body
  """
  @spec post(String.t(), request_opts()) :: {:ok, response()} | {:error, term()}
  def post(url, opts \\ []) do
    request(:post, url, opts)
  end

  @doc """
  Make a generic HTTP request.
  """
  @spec request(atom(), String.t(), request_opts()) :: {:ok, response()} | {:error, term()}
  def request(method, url, opts \\ []) do
    uri = URI.parse(url)
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    {body, content_type} = build_body(opts)
    headers = build_headers(opts, content_type)

    scheme = uri_scheme(uri.scheme)
    port = uri.port || default_port(uri.scheme)
    path = build_path(uri)

    with {:ok, conn} <- connect(scheme, uri.host, port, timeout),
         {:ok, conn, request_ref} <- send_request(conn, method, path, headers, body),
         {:ok, response} <- receive_response(conn, request_ref, timeout) do
      Mint.HTTP.close(conn)
      {:ok, response}
    else
      {:error, _conn, reason} -> {:error, reason}
      {:error, reason} -> {:error, reason}
    end
  end

  # Connect to host
  defp connect(scheme, host, port, timeout) do
    transport_opts = [timeout: timeout]

    opts =
      case scheme do
        :https ->
          [
            transport_opts: transport_opts ++ [cacerts: :public_key.cacerts_get()]
          ]

        :http ->
          [transport_opts: transport_opts]
      end

    Mint.HTTP.connect(scheme, host, port, opts)
  end

  # Send the HTTP request
  defp send_request(conn, method, path, headers, nil) do
    Mint.HTTP.request(conn, to_string(method) |> String.upcase(), path, headers, nil)
  end

  defp send_request(conn, method, path, headers, body) do
    Mint.HTTP.request(conn, to_string(method) |> String.upcase(), path, headers, body)
  end

  # Receive and accumulate response
  defp receive_response(conn, request_ref, timeout) do
    receive_response_loop(conn, request_ref, timeout, %{status: nil, headers: [], body: []})
  end

  defp receive_response_loop(conn, request_ref, timeout, acc) do
    receive do
      message ->
        case Mint.HTTP.stream(conn, message) do
          :unknown ->
            receive_response_loop(conn, request_ref, timeout, acc)

          {:ok, conn, responses} ->
            acc = process_responses(responses, request_ref, acc)

            if response_complete?(responses, request_ref) do
              {:ok, finalize_response(acc)}
            else
              receive_response_loop(conn, request_ref, timeout, acc)
            end

          {:error, _conn, reason, _responses} ->
            {:error, reason}
        end
    after
      timeout ->
        {:error, :timeout}
    end
  end

  defp process_responses(responses, request_ref, acc) do
    Enum.reduce(responses, acc, fn
      {:status, ^request_ref, status}, acc ->
        %{acc | status: status}

      {:headers, ^request_ref, headers}, acc ->
        %{acc | headers: acc.headers ++ headers}

      {:data, ^request_ref, data}, acc ->
        %{acc | body: [acc.body | [data]]}

      {:done, ^request_ref}, acc ->
        acc

      _other, acc ->
        acc
    end)
  end

  defp response_complete?(responses, request_ref) do
    Enum.any?(responses, fn
      {:done, ^request_ref} -> true
      _ -> false
    end)
  end

  defp finalize_response(acc) do
    body = IO.iodata_to_binary(acc.body)
    content_type = get_content_type(acc.headers)

    # Try to decode JSON if content-type indicates it
    decoded_body =
      if json_content_type?(content_type) do
        decode_json(body)
      else
        body
      end

    %{
      status: acc.status,
      headers: acc.headers,
      body: decoded_body
    }
  end

  defp get_content_type(headers) do
    Enum.find_value(headers, "", fn
      {"content-type", value} -> value
      {key, value} when is_binary(key) -> if String.downcase(key) == "content-type", do: value
      _ -> nil
    end)
  end

  # Check if content-type indicates JSON
  # Handles: application/json, application/did+json, application/ld+json,
  # application/did+ld+json, text/json, etc.
  defp json_content_type?(content_type) when is_binary(content_type) do
    lower = String.downcase(content_type)

    String.contains?(lower, "json") or
      String.starts_with?(lower, "application/json") or
      String.starts_with?(lower, "text/json")
  end

  defp json_content_type?(_), do: false

  defp decode_json(body) when byte_size(body) > 0 do
    case Jason.decode(body) do
      {:ok, decoded} ->
        decoded

      {:error, error} ->
        Logger.debug(
          "[HTTP] Failed to decode JSON: #{inspect(error)}, body: #{String.slice(body, 0, 200)}"
        )

        body
    end
  end

  defp decode_json(body), do: body

  # Build request body
  defp build_body(opts) do
    cond do
      json = Keyword.get(opts, :json) ->
        {Jason.encode!(json), "application/json"}

      body = Keyword.get(opts, :body) ->
        content_type = Keyword.get(opts, :content_type, "application/octet-stream")
        {body, content_type}

      true ->
        {nil, nil}
    end
  end

  # Build headers list
  defp build_headers(opts, content_type) do
    base = [{"accept", "application/json"}, {"user-agent", "MediaLibrary/0.1.0"}]
    custom = Keyword.get(opts, :headers, [])

    headers =
      if content_type do
        [{"content-type", content_type} | base]
      else
        base
      end

    headers ++ custom
  end

  # Build request path with query string
  defp build_path(%URI{path: nil, query: nil}), do: "/"
  defp build_path(%URI{path: nil, query: query}), do: "/?" <> query
  defp build_path(%URI{path: path, query: nil}), do: path
  defp build_path(%URI{path: path, query: query}), do: path <> "?" <> query

  defp uri_scheme("https"), do: :https
  defp uri_scheme("http"), do: :http
  defp uri_scheme(_), do: :https

  defp default_port("https"), do: 443
  defp default_port("http"), do: 80
  defp default_port(_), do: 443
end
