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

  alias Exosphere.ATProto.HTTP.Behaviour

  @behaviour Behaviour

  @default_timeout 30_000
  @user_agent "Exosphere/#{Mix.Project.config()[:version]}"

  # The response/request shapes live on the behaviour (the contract every
  # adapter and test mock implements); re-exported here for the public API.
  @type json_term :: Behaviour.json_term()
  @type response :: Behaviour.response()
  @type request_opts :: Behaviour.request_opts()

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

  GET/HEAD redirects (301/302/303/307/308) are followed automatically, up to
  5 hops. This matters for atproto endpoints: a relay may redirect
  `com.atproto.sync.getRepo` to the PDS that actually hosts the account.
  Redirect handling can be disabled with `follow_redirects: false`.
  """
  @spec request(atom(), String.t(), request_opts()) :: {:ok, response()} | {:error, term()}
  def request(method, url, opts \\ []) do
    do_request(method, url, opts, 0)
  end

  @max_redirects 5

  defp do_request(method, url, opts, redirects) do
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

      case redirect_location(response) do
        nil ->
          {:ok, response}

        location when method in [:get, :head] ->
          cond do
            not Keyword.get(opts, :follow_redirects, true) -> {:ok, response}
            redirects >= @max_redirects -> {:error, :too_many_redirects}
            true -> do_request(method, absolute_uri(uri, location), opts, redirects + 1)
          end

        _ ->
          {:ok, response}
      end
    else
      # Every error path that holds a conn (send/receive failures and receive
      # timeouts) must close it, or each failed request leaks a socket.
      {:error, conn, reason} ->
        Mint.HTTP.close(conn)
        {:error, reason}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp redirect_location(%{status: status, headers: headers})
       when status in [301, 302, 303, 307, 308] do
    Enum.find_value(headers, fn
      {"location", value} ->
        value

      {key, value} when is_binary(key) ->
        if String.downcase(key) == "location", do: value

      _ ->
        nil
    end)
  end

  defp redirect_location(_), do: nil

  # Resolve a (possibly relative) Location header against the request URI.
  defp absolute_uri(base, "/" <> _ = location) do
    base_scheme = base.scheme || "https"
    "#{base_scheme}://#{base.host}:#{base.port || default_port(base.scheme)}#{location}"
  end

  defp absolute_uri(_base, location), do: location

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

  # Receive and accumulate response. Messages are drained in batches: a plain
  # `receive`-per-message loop rescans the whole mailbox for every message,
  # which is quadratic and crawls on multi-megabyte responses (tens of
  # thousands of socket messages).
  defp receive_response(conn, request_ref, timeout) do
    receive_response_loop(conn, request_ref, timeout, %{status: nil, headers: [], body: []})
  end

  defp receive_response_loop(conn, request_ref, timeout, acc) do
    # Block for the first message (bounded by the timeout), then greedily
    # drain everything already in the mailbox.
    messages =
      receive do
        message -> drain_mailbox([message])
      after
        timeout ->
          {:error, conn, :timeout}
      end

    case messages do
      {:error, conn, :timeout} ->
        {:error, conn, :timeout}

      messages ->
        stream_messages(conn, messages, request_ref, timeout, acc)
    end
  end

  defp drain_mailbox(acc) do
    receive do
      message -> drain_mailbox([message | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp stream_messages(conn, [], request_ref, timeout, acc),
    do: receive_response_loop(conn, request_ref, timeout, acc)

  defp stream_messages(conn, [message | rest], request_ref, timeout, acc) do
    case Mint.HTTP.stream(conn, message) do
      :unknown ->
        stream_messages(conn, rest, request_ref, timeout, acc)

      {:ok, conn, responses} ->
        acc = process_responses(responses, request_ref, acc)

        if response_complete?(responses, request_ref) do
          {:ok, finalize_response(acc)}
        else
          stream_messages(conn, rest, request_ref, timeout, acc)
        end

      {:error, conn, reason, _responses} ->
        {:error, conn, reason}
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
    base = [{"accept", "application/json"}, {"user-agent", @user_agent}]
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
