defmodule Exosphere.ATProto.Spaces.XRPC do
  @moduledoc false
  # Shared transport for the OAuth-authenticated space administration clients
  # (`Spaces.Space`, `Spaces.Memberspace`, `Spaces.Managedspace`).
  #
  # Authorization is the caller's, in one of two shapes:
  #
  #   * `headers: [{"authorization", ...}]` — sent as given (a Bearer token,
  #     or service auth for `checkUserAccess`);
  #   * `session: %OAuth.Session{}` — a DPoP-bound OAuth session, sent through
  #     `OAuth.Request.authorized/6` so DPoP nonce challenges are retried.
  #
  # XRPC error bodies (`{"error": name, "message": ...}`) surface as
  # `{:error, {:http_error, status, name}}`; bodiless failures as
  # `{:error, {:http_error, status}}`.

  alias Exosphere.ATProto.HTTP
  alias Exosphere.ATProto.OAuth.{Request, Session}

  @type auth :: [headers: [{String.t(), String.t()}]] | [session: Session.t()]

  @spec query(String.t(), String.t(), map(), keyword(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def query(host, nsid, params, auth, opts) do
    url = url(host, nsid) <> "?" <> URI.encode_query(compact(params))

    host
    |> request(:get, url, HTTP.take_request_opts(opts), auth, opts)
    |> classify()
  end

  @spec procedure(String.t(), String.t(), map(), keyword(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def procedure(host, nsid, body, auth, opts) do
    request_opts = Keyword.put(HTTP.take_request_opts(opts), :json, compact(body))

    host
    |> request(:post, url(host, nsid), request_opts, auth, opts)
    |> classify()
  end

  @doc false
  # A raw-body procedure (`application/octet-stream` input, e.g. a STAR
  # archive). The response is classified like any other.
  @spec procedure_bytes(String.t(), String.t(), binary(), keyword(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def procedure_bytes(host, nsid, bytes, auth, opts) when is_binary(bytes) do
    request_opts =
      opts
      |> HTTP.take_request_opts()
      |> Keyword.put(:body, bytes)
      |> Keyword.put(:content_type, "application/octet-stream")

    host
    |> request(:post, url(host, nsid), request_opts, auth, opts)
    |> classify()
  end

  @doc false
  # A query whose output is raw bytes (`application/octet-stream`).
  @spec query_bytes(String.t(), String.t(), map(), keyword(), keyword()) ::
          {:ok, binary()} | {:error, term()}
  def query_bytes(host, nsid, params, auth, opts) do
    url = url(host, nsid) <> "?" <> URI.encode_query(compact(params))

    case request(host, :get, url, HTTP.take_request_opts(opts), auth, opts) do
      {:ok, %{status: 200, body: body}} when is_binary(body) -> {:ok, body}
      other -> classify(other)
    end
  end

  @spec classify({:ok, HTTP.response()} | {:error, term()}) :: {:ok, map()} | {:error, term()}
  def classify({:ok, %{status: 200, body: body}}) when is_map(body), do: {:ok, body}
  # An input-less, output-less procedure may answer 200 with an empty body.
  def classify({:ok, %{status: 200, body: body}}) when body in [nil, ""], do: {:ok, %{}}

  def classify({:ok, %{status: status, body: %{"error" => error}}}) when is_binary(error),
    do: {:error, {:http_error, status, error}}

  def classify({:ok, %{status: status}}), do: {:error, {:http_error, status}}
  def classify({:error, _} = error), do: error

  defp request(_host, method, url, request_opts, auth, opts) when is_list(auth) do
    http = Keyword.get(opts, :http, HTTP)

    cond do
      headers = auth[:headers] ->
        http.request(method, url, Keyword.put(request_opts, :headers, headers))

      match?(%Session{}, auth[:session]) ->
        session = auth[:session]

        Request.authorized(
          http,
          method,
          url,
          request_opts,
          session.dpop_key,
          session.access_token
        )

      true ->
        {:error, :invalid_auth}
    end
  end

  defp url(host, nsid), do: "#{String.trim_trailing(host, "/")}/xrpc/#{nsid}"

  defp compact(map), do: map |> Enum.reject(fn {_k, v} -> is_nil(v) end) |> Map.new()
end
