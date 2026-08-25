defmodule Exosphere.ATProto.XRPC.Client do
  @moduledoc """
  XRPC HTTP client for Exosphere.ATProto.

  XRPC is the HTTP API layer for Exosphere.ATProto. It provides:
  - **Queries** (GET requests) for reading data
  - **Procedures** (POST requests) for mutations

  ## Examples

      # Create a client for a PDS
      client = Exosphere.ATProto.XRPC.Client.new("https://bsky.social")

      # Make an unauthenticated query
      {:ok, response} = Exosphere.ATProto.XRPC.Client.query(client, "com.atproto.identity.resolveHandle",
        handle: "atproto.com"
      )

      # Make an authenticated procedure
      client = Exosphere.ATProto.XRPC.Client.new("https://bsky.social", access_token: "...")
      {:ok, response} = Exosphere.ATProto.XRPC.Client.procedure(client, "com.atproto.repo.createRecord",
        repo: "did:plc:...",
        collection: "app.bsky.feed.post",
        record: %{text: "Hello!"}
      )
  """

  alias Exosphere.ATProto.HTTP
  alias Exosphere.ATProto.OAuth.Request
  alias Exosphere.ATProto.XRPC.Error

  @enforce_keys [:base_url]
  defstruct [:base_url, :access_token, :refresh_token, :timeout, :http, :dpop]

  @type t :: %__MODULE__{
          base_url: String.t(),
          access_token: String.t() | nil,
          refresh_token: String.t() | nil,
          timeout: pos_integer() | nil,
          http: module() | nil,
          dpop: map() | nil
        }

  @type query_params :: keyword() | map()
  @type procedure_body :: map()

  # `Error.t()` for XRPC error responses; anything else is a transport failure
  # (timeout, too_many_redirects, adapter error) passed through from the HTTP
  # adapter.
  @type error :: Error.t() | term()

  @default_timeout 30_000

  @doc """
  Create a new XRPC client.

  ## Options

  - `:access_token` - access token for authentication
  - `:refresh_token` - refresh token
  - `:dpop` - private DPoP JWK (from `Exosphere.ATProto.OAuth.Session`).
    When set together with `:access_token`, requests are DPoP-signed
    (`Authorization: DPoP ...` plus a per-request proof header, with
    automatic nonce retry) instead of plain Bearer
  - `:timeout` - Request timeout in milliseconds (default: 30_000)

  ## Examples

      # Unauthenticated client
      client = Exosphere.ATProto.XRPC.Client.new("https://bsky.social")

      # Authenticated client
      client = Exosphere.ATProto.XRPC.Client.new("https://bsky.social",
        access_token: "eyJ...",
        refresh_token: "eyJ..."
      )
  """
  @spec new(String.t(), keyword()) :: t()
  def new(base_url, opts \\ []) do
    base_url = String.trim_trailing(base_url, "/")

    %__MODULE__{
      base_url: base_url,
      access_token: Keyword.get(opts, :access_token),
      refresh_token: Keyword.get(opts, :refresh_token),
      timeout: Keyword.get(opts, :timeout, @default_timeout),
      http: Keyword.get(opts, :http, HTTP),
      dpop: Keyword.get(opts, :dpop)
    }
  end

  @doc """
  Set the access token on a client.
  """
  @spec with_token(t(), String.t()) :: t()
  def with_token(%__MODULE__{} = client, token) do
    %{client | access_token: token}
  end

  @doc """
  Make an XRPC query (HTTP GET).

  Queries are for reading data and are idempotent.

  ## Examples

      {:ok, %{"did" => "did:plc:..."}} =
        Exosphere.ATProto.XRPC.Client.query(client, "com.atproto.identity.resolveHandle",
          handle: "atproto.com"
        )
  """
  @spec query(t(), String.t(), query_params()) :: {:ok, HTTP.json_term()} | {:error, error()}
  def query(%__MODULE__{} = client, nsid, params \\ []) do
    client
    |> execute(:get, build_url(client, nsid, params), [])
    |> map_response()
  end

  @doc """
  Make an XRPC procedure (HTTP POST).

  Procedures are for mutations and may not be idempotent.

  ## Examples

      {:ok, %{"uri" => "at://...", "cid" => "bafyrei..."}} =
        Exosphere.ATProto.XRPC.Client.procedure(client, "com.atproto.repo.createRecord",
          repo: "did:plc:...",
          collection: "app.bsky.feed.post",
          record: %{"$type" => "app.bsky.feed.post", "text" => "Hello!"}
        )
  """
  @spec procedure(t(), String.t(), procedure_body() | keyword(), query_params()) ::
          {:ok, HTTP.json_term()} | {:error, error()}
  def procedure(%__MODULE__{} = client, nsid, body \\ %{}, params \\ []) do
    url = build_url(client, nsid, params)
    json_body = if is_list(body), do: Map.new(body), else: body

    client
    |> execute(:post, url, json: json_body)
    |> map_response()
  end

  @doc """
  Upload a blob to the PDS.

  ## Examples

      {:ok, %{"blob" => blob}} =
        Exosphere.ATProto.XRPC.Client.upload_blob(client, image_bytes, "image/jpeg")
  """
  @spec upload_blob(t(), binary(), String.t()) :: {:ok, map()} | {:error, error()}
  def upload_blob(%__MODULE__{} = client, data, content_type) when is_binary(data) do
    url = build_url(client, "com.atproto.repo.uploadBlob")

    client
    |> execute(:post, url, body: data, content_type: content_type)
    |> map_response()
  end

  @doc """
  Create a session (login).

  ## Examples

      {:ok, session} = Exosphere.ATProto.XRPC.Client.create_session(client, "user@example.com", "password")
      client = Exosphere.ATProto.XRPC.Client.with_token(client, session["accessJwt"])
  """
  @spec create_session(t(), String.t(), String.t()) :: {:ok, map()} | {:error, error()}
  def create_session(%__MODULE__{} = client, identifier, password) do
    procedure(client, "com.atproto.server.createSession", %{
      identifier: identifier,
      password: password
    })
  end

  @doc """
  Refresh a session using the refresh token.

  Returns `{:error, :no_refresh_token}` when the client has no refresh token.
  """
  @spec refresh_session(t()) :: {:ok, map()} | {:error, error()}
  def refresh_session(%__MODULE__{refresh_token: nil}) do
    {:error, :no_refresh_token}
  end

  def refresh_session(%__MODULE__{} = client) do
    url = build_url(client, "com.atproto.server.refreshSession")
    headers = [{"authorization", "Bearer #{client.refresh_token}"}]

    case client.http.post(url, headers: headers, timeout: client.timeout) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        {:error, Error.from_response(status, body)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Get a record from a repository.

  ## Examples

      {:ok, record} = Exosphere.ATProto.XRPC.Client.get_record(client,
        repo: "did:plc:...",
        collection: "app.bsky.feed.post",
        rkey: "3jui7kd2lry2e"
      )
  """
  @spec get_record(t(), keyword()) :: {:ok, map()} | {:error, error()}
  def get_record(%__MODULE__{} = client, params) do
    query(client, "com.atproto.repo.getRecord", params)
  end

  @doc """
  List records from a repository.

  ## Examples

      {:ok, %{"records" => records}} = Exosphere.ATProto.XRPC.Client.list_records(client,
        repo: "did:plc:...",
        collection: "app.bsky.feed.post",
        limit: 50
      )
  """
  @spec list_records(t(), keyword()) :: {:ok, map()} | {:error, error()}
  def list_records(%__MODULE__{} = client, params) do
    query(client, "com.atproto.repo.listRecords", params)
  end

  @doc """
  Describe a repository.

  ## Examples

      {:ok, info} = Exosphere.ATProto.XRPC.Client.describe_repo(client, "did:plc:...")
  """
  @spec describe_repo(t(), String.t()) :: {:ok, map()} | {:error, error()}
  def describe_repo(%__MODULE__{} = client, repo) do
    query(client, "com.atproto.repo.describeRepo", repo: repo)
  end

  # Execute a request. DPoP sessions (key + access token) go through the
  # shared OAuth executor, which signs per-request proofs and retries nonce
  # challenges; everything else stays a plain request with Bearer auth.
  # The plain path keeps calling get/post (not request/3) so downstream HTTP
  # fakes written against the original contract keep working.
  defp execute(%__MODULE__{dpop: nil} = client, method, url, opts) do
    request_opts = [headers: build_headers(client), timeout: client.timeout] ++ opts

    case method do
      :get -> client.http.get(url, request_opts)
      :post -> client.http.post(url, request_opts)
    end
  end

  defp execute(%__MODULE__{dpop: key, access_token: token} = client, method, url, opts)
       when is_map(key) and is_binary(token) do
    Request.authorized(client.http, method, url, [timeout: client.timeout] ++ opts, key, token)
  end

  defp execute(%__MODULE__{} = client, method, url, opts) do
    client.http.request(method, url, [timeout: client.timeout] ++ opts)
  end

  defp map_response({:ok, %{status: 200, body: body}}), do: {:ok, body}

  defp map_response({:ok, %{status: status, body: body}}),
    do: {:error, Error.from_response(status, body)}

  defp map_response({:error, reason}), do: {:error, reason}

  # Build the full URL for an XRPC endpoint
  defp build_url(%__MODULE__{base_url: base}, nsid, params \\ []) do
    query_string = build_query_string(params)

    if query_string == "" do
      "#{base}/xrpc/#{nsid}"
    else
      "#{base}/xrpc/#{nsid}?#{query_string}"
    end
  end

  # Build query string from params
  defp build_query_string([]), do: ""

  defp build_query_string(params) when is_list(params) do
    params
    |> Enum.map_join("&", fn {k, v} ->
      "#{URI.encode_www_form(to_string(k))}=#{URI.encode_www_form(to_string(v))}"
    end)
  end

  defp build_query_string(params) when is_map(params) do
    build_query_string(Map.to_list(params))
  end

  # Build headers for the request
  defp build_headers(%__MODULE__{access_token: nil}) do
    []
  end

  defp build_headers(%__MODULE__{access_token: token}) do
    [{"authorization", "Bearer #{token}"}]
  end
end
