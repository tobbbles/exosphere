defmodule Exosphere.ATProto.Spaces.XRPC do
  @moduledoc false
  # Shared transport for the OAuth-authenticated space administration clients
  # (`Spaces.Space`, `Spaces.Memberspace`, `Spaces.Managedspace`).
  #
  # Authorization is the caller's, in one of three shapes:
  #
  #   * `headers: [{"authorization", ...}]` — sent as given (a Bearer token,
  #     or a pre-minted service auth token);
  #   * `session: %OAuth.Session{}` — a DPoP-bound OAuth session, sent through
  #     `OAuth.Request.authorized/6` so DPoP nonce challenges are retried;
  #   * `service_auth: [iss:, aud:, key:]` — an inter-service JWT minted per
  #     request by `XRPC.ServiceAuth.sign/2`, with `lxm` set to the method's
  #     NSID (`key` is the issuer's private signing JWK; `kid:` and
  #     `expires_in:` pass through).
  #
  # XRPC error bodies (`{"error": name, "message": ...}`) surface as
  # `{:error, {:http_error, status, name}}`; bodiless failures as
  # `{:error, {:http_error, status}}`. The error names introduced or renamed
  # by atproto `atproto-spaces-lexicon-review` / `atproto-spaces-cleanup`
  # (4037310) are typed instead (see `@typed_errors`).

  alias Exosphere.ATProto.HTTP
  alias Exosphere.ATProto.OAuth.{Request, Session}
  alias Exosphere.ATProto.XRPC.ServiceAuth

  @star_content_type "application/vnd.dasl.star"

  @type auth ::
          [headers: [{String.t(), String.t()}]]
          | [session: Session.t()]
          | [service_auth: keyword()]

  @spec query(String.t(), String.t(), map(), keyword(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def query(host, nsid, params, auth, opts) do
    url = url(host, nsid) <> "?" <> URI.encode_query(compact(params))

    nsid
    |> request(:get, url, HTTP.take_request_opts(opts), auth, opts)
    |> classify()
  end

  @spec procedure(String.t(), String.t(), map(), keyword(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def procedure(host, nsid, body, auth, opts) do
    request_opts = Keyword.put(HTTP.take_request_opts(opts), :json, compact(body))

    nsid
    |> request(:post, url(host, nsid), request_opts, auth, opts)
    |> classify()
  end

  @doc false
  # A raw-body procedure taking a STAR archive (`application/vnd.dasl.star`
  # input since atproto `atproto-spaces-cleanup` 4037310; it was
  # `application/octet-stream`). The response is classified like any other.
  @spec procedure_bytes(String.t(), String.t(), binary(), keyword(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def procedure_bytes(host, nsid, bytes, auth, opts) when is_binary(bytes) do
    request_opts =
      opts
      |> HTTP.take_request_opts()
      |> Keyword.put(:body, bytes)
      |> Keyword.put(:content_type, @star_content_type)

    nsid
    |> request(:post, url(host, nsid), request_opts, auth, opts)
    |> classify()
  end

  @doc false
  # A query whose output is a STAR archive (`application/vnd.dasl.star`).
  @spec query_bytes(String.t(), String.t(), map(), keyword(), keyword()) ::
          {:ok, binary()} | {:error, term()}
  def query_bytes(host, nsid, params, auth, opts) do
    url = url(host, nsid) <> "?" <> URI.encode_query(compact(params))

    case request(nsid, :get, url, HTTP.take_request_opts(opts), auth, opts) do
      {:ok, %{status: 200, body: body}} when is_binary(body) -> {:ok, body}
      other -> classify(other)
    end
  end

  # The error names upstream introduced or renamed at 4037310, typed so callers
  # match an atom rather than a string: `NotAuthorized` (was `NotSpaceOwner`),
  # `InvalidCursor` (was `MalformedCursor`, and newly declared on the listing
  # methods), and the import refusals `InvalidSpaceMeta`, `InvalidRepoFile`
  # and `RepoMismatch`.
  @typed_errors %{
    "NotAuthorized" => :not_authorized,
    "InvalidCursor" => :invalid_cursor,
    "InvalidSpaceMeta" => :invalid_space_meta,
    "InvalidRepoFile" => :invalid_repo_file,
    "RepoMismatch" => :repo_mismatch
  }

  @doc false
  @spec typed_errors() :: %{String.t() => atom()}
  def typed_errors, do: @typed_errors

  @spec classify({:ok, HTTP.response()} | {:error, term()}) :: {:ok, map()} | {:error, term()}
  def classify({:ok, %{status: 200, body: body}}) when is_map(body), do: {:ok, body}
  # An input-less, output-less procedure may answer 200 with an empty body.
  def classify({:ok, %{status: 200, body: body}}) when body in [nil, ""], do: {:ok, %{}}

  def classify({:ok, %{body: %{"error" => error}}}) when is_map_key(@typed_errors, error),
    do: {:error, Map.fetch!(@typed_errors, error)}

  def classify({:ok, %{status: status, body: %{"error" => error}}}) when is_binary(error),
    do: {:error, {:http_error, status, error}}

  def classify({:ok, %{status: status}}), do: {:error, {:http_error, status}}
  def classify({:error, _} = error), do: error

  defp request(nsid, method, url, request_opts, auth, opts) when is_list(auth) do
    http = Keyword.get(opts, :http, HTTP)

    cond do
      headers = auth[:headers] ->
        http.request(method, url, Keyword.put(request_opts, :headers, headers))

      service_auth = auth[:service_auth] ->
        with {:ok, headers} <- service_auth_headers(service_auth, nsid) do
          http.request(method, url, Keyword.put(request_opts, :headers, headers))
        end

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

  defp service_auth_headers(service_auth, nsid) when is_list(service_auth) do
    {key, sign_opts} = Keyword.pop(service_auth, :key)
    ServiceAuth.headers(Keyword.put(sign_opts, :lxm, nsid), key)
  end

  defp service_auth_headers(_, _), do: {:error, :invalid_auth}

  defp url(host, nsid), do: "#{String.trim_trailing(host, "/")}/xrpc/#{nsid}"

  defp compact(map), do: map |> Enum.reject(fn {_k, v} -> is_nil(v) end) |> Map.new()
end
