defmodule Exosphere.ATProto.OAuth.Session do
  @moduledoc """
  A DPoP-bound ATProto OAuth session: the tokens, the session DPoP key, and
  everything needed to refresh and to make authorized XRPC requests.

  Produced by `Flow.callback/3`. The struct is plain data — refresh it with
  `refresh/2`, persist it with `to_map/1`, and hand it to
  `Exosphere.OAuth.Session` (the GenServer wrapper) or use it directly with
  `Exosphere.ATProto.Repo` (which accepts a session with `access_token` and
  `dpop_private_key`).

  Refresh tokens are single-use (rotating): after every successful refresh,
  store the new session — the old refresh token is dead. A
  `{:error, :invalid_grant}` from refresh means the refresh token was reused
  or revoked and the session must be discarded.
  """

  alias Exosphere.ATProto.OAuth.{Client, Discovery, Request, ServerMetadata}

  defstruct [
    :sub,
    :access_token,
    :refresh_token,
    :scope,
    :expires_at,
    :dpop_key,
    :pds,
    :client,
    :auth_server
  ]

  @type t :: %__MODULE__{
          sub: String.t(),
          access_token: String.t(),
          refresh_token: String.t() | nil,
          scope: [String.t()],
          expires_at: pos_integer() | nil,
          dpop_key: map(),
          pds: String.t() | nil,
          client: Client.t(),
          auth_server: ServerMetadata.t()
        }

  @client_assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

  @doc """
  Build a session from a token response.

  ## Options

  - `:sub`, `:access_token`, `:refresh_token`, `:scope` (list or
    space-separated string), `:expires_in` (seconds) or `:expires_at`
    (unix seconds), `:dpop_key`, `:client`, `:auth_server`, `:pds`
  - `:expected_did` - when set, `sub` must match it
  - `:http` - HTTP module for the server-flow subject verification
  """
  @spec new(keyword() | map()) :: {:ok, t()} | {:error, term()}
  def new(opts) do
    scope = normalize_scope(opts[:scope])
    expires_at = expires_at(opts)

    with :ok <- check_fields(opts),
         :ok <- check_scope(scope),
         :ok <- check_subject(opts),
         {:ok, pds} <- resolve_pds(opts) do
      {:ok,
       %__MODULE__{
         sub: opts[:sub],
         access_token: opts[:access_token],
         refresh_token: opts[:refresh_token],
         scope: scope,
         expires_at: expires_at,
         dpop_key: opts[:dpop_key],
         pds: pds,
         client: opts[:client],
         auth_server: opts[:auth_server]
       }}
    end
  end

  @doc """
  Like `new/1`, but raises on invalid input.
  """
  @spec new!(keyword()) :: t()
  def new!(opts) do
    case new(opts) do
      {:ok, session} -> session
      {:error, reason} -> raise ArgumentError, "invalid session: #{inspect(reason)}"
    end
  end

  @doc """
  Refresh the session: exchange the (single-use) refresh token for a new
  token pair.

  On success returns the rotated session — replace your stored copy. On
  `{:error, {:refresh_failed, 400, _}}` (invalid/reused refresh token), the
  session is unrecoverable: discard it and re-authorize.
  """
  @spec refresh(t(), keyword()) :: {:ok, t()} | {:error, term()}
  def refresh(session, opts \\ [])

  def refresh(%__MODULE__{refresh_token: nil}, _opts), do: {:error, :no_refresh_token}

  def refresh(%__MODULE__{} = session, opts) do
    %ServerMetadata{} = auth_server = session.auth_server

    form =
      %{
        "grant_type" => "refresh_token",
        "refresh_token" => session.refresh_token,
        "client_id" => Client.client_id(session.client)
      }
      |> Map.merge(assertion_params(session.client, auth_server))

    with {:ok, %{status: 200, body: body}} when is_map(body) <-
           Request.authorized(
             opts[:http],
             :post,
             auth_server.token_endpoint,
             [form: form, timeout: opts[:timeout]],
             session.dpop_key,
             nil
           ),
         :ok <- check_subject_match(session.sub, body["sub"]),
         :ok <- check_token_type(body["token_type"]),
         scope = normalize_scope(body["scope"]),
         :ok <- check_scope(scope) do
      {:ok,
       %{
         session
         | access_token: body["access_token"],
           refresh_token: body["refresh_token"] || session.refresh_token,
           scope: scope,
           expires_at: expires_at(expires_in: body["expires_in"])
       }}
    else
      {:ok, %{status: status, body: body}} ->
        {:error, {:refresh_failed, status, body}}

      {:error, _reason} = error ->
        error
    end
  end

  @doc """
  Whether the access token has expired (with a small clock-skew allowance).

  `:now` overrides the current time (tests).
  """
  @spec expired?(t(), keyword()) :: boolean()
  def expired?(session, opts \\ [])

  def expired?(%__MODULE__{expires_at: nil}, _opts), do: false

  def expired?(%__MODULE__{expires_at: expires_at}, opts) do
    now = Keyword.get(opts, :now, System.system_time(:second))
    now >= expires_at - 30
  end

  @doc """
  The session as a plain, `Jason`-encodable map for persistence.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = session) do
    %{
      "sub" => session.sub,
      "access_token" => session.access_token,
      "refresh_token" => session.refresh_token,
      "scope" => session.scope,
      "expires_at" => session.expires_at,
      "dpop_key" => session.dpop_key,
      "pds" => session.pds,
      "client" => Client.to_map(session.client),
      "auth_server" => ServerMetadata.to_map(session.auth_server)
    }
  end

  @doc """
  Rebuild a session serialized with `to_map/1`.
  """
  @spec from_map(map()) :: {:ok, t()} | {:error, :invalid_session}
  def from_map(map) when is_map(map) do
    with {:ok, client} <- Client.from_map(map["client"] || %{}),
         {:ok, auth_server} <- ServerMetadata.from_map(map["auth_server"] || %{}) do
      {:ok,
       %__MODULE__{
         sub: map["sub"],
         access_token: map["access_token"],
         refresh_token: map["refresh_token"],
         scope: map["scope"] || [],
         expires_at: map["expires_at"],
         dpop_key: map["dpop_key"],
         pds: map["pds"],
         client: client,
         auth_server: auth_server
       }}
    end
  end

  def from_map(_), do: {:error, :invalid_session}

  defp check_fields(opts) do
    Enum.reduce_while([:sub, :access_token, :dpop_key, :client, :auth_server], :ok, fn field,
                                                                                       :ok ->
      if is_nil(opts[field]),
        do: {:halt, {:error, {:missing_session_field, field}}},
        else: {:cont, :ok}
    end)
  end

  defp check_scope(scope),
    do: if("atproto" in scope, do: :ok, else: {:error, :atproto_scope_required})

  defp check_subject(opts) do
    expected = opts[:expected_did]

    if is_nil(expected) or opts[:sub] == expected,
      do: :ok,
      else: {:error, :subject_mismatch}
  end

  # The PDS is known up-front when the flow started from an identity (it is
  # carried on the request context). For the server flow — where the user's
  # DID is only learned from the token response — the subject is verified
  # against the issuer by resolving its DID document.
  defp resolve_pds(opts) do
    if pds = opts[:pds] do
      {:ok, pds}
    else
      verify_server_flow_subject(opts)
    end
  end

  defp verify_server_flow_subject(opts) do
    issuer = opts[:auth_server].issuer

    discovery_opts =
      if http = opts[:http],
        do: [http: http],
        else: []

    case Discovery.verify_subject(opts[:sub], issuer, discovery_opts) do
      {:ok, %{pds: pds}} -> {:ok, pds}
      {:error, reason} -> {:error, {:subject_verification_failed, reason}}
    end
  end

  defp check_subject_match(expected, sub) when is_binary(sub) do
    if sub == expected, do: :ok, else: {:error, :subject_mismatch}
  end

  defp check_subject_match(_, _), do: {:error, :missing_subject}

  defp check_token_type(type) when is_binary(type) do
    if String.downcase(type) == "dpop", do: :ok, else: {:error, :unsupported_token_type}
  end

  defp check_token_type(_), do: {:error, :unsupported_token_type}

  defp assertion_params(client, auth_server) do
    if Client.confidential?(client) do
      with {:ok, assertion} <- Client.assertion(client, auth_server.issuer) do
        %{"client_assertion_type" => @client_assertion_type, "client_assertion" => assertion}
      end
    else
      %{}
    end
  end

  defp normalize_scope(scope) when is_binary(scope), do: String.split(scope)
  defp normalize_scope(scope) when is_list(scope), do: scope
  defp normalize_scope(_), do: []

  defp expires_at(opts) do
    cond do
      expires_at = opts[:expires_at] -> expires_at
      expires_in = opts[:expires_in] -> System.system_time(:second) + expires_in
      true -> nil
    end
  end
end
