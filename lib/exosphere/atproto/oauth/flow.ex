defmodule Exosphere.ATProto.OAuth.Flow do
  @moduledoc """
  The ATProto OAuth authorization-code flow: PAR → authorize redirect →
  callback → token exchange.

  `authorize_url/3` starts the flow (returns the URL to send the user to
  plus an opaque `RequestContext` the caller must persist — Plug session,
  database, GenServer — between requests). `callback/3` completes it with
  the query parameters the authorization server redirected back with, and
  produces a `Exosphere.ATProto.OAuth.Session`.

  ## Examples

      {:ok, resolved} = Discovery.resolve("alice.example.com")
      client = Client.new!(metadata: metadata, key: key, redirect_uri: "https://app.example.com/oauth/callback")
      {:ok, {url, ctx}} = Flow.authorize_url(client, resolved)
      # ... user approves, AS redirects to redirect_uri?code=..&state=..&iss=..
      {:ok, session} = Flow.callback(ctx, conn.query_params)
  """

  alias Exosphere.ATProto.OAuth.{
    Client,
    Discovery,
    DPoP,
    PKCE,
    Request,
    RequestContext,
    ServerMetadata,
    Session
  }

  @client_assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

  @doc """
  Push a PAR request and build the authorization URL.

  ## Options

  - `:scope` - scopes to request (default: the client metadata scope,
    filtered to what the server supports)
  - `:state` - explicit state value (default: generated)
  - `:http` - HTTP module implementing `HTTP.Behaviour` (testing)
  - `:timeout` - request timeout in milliseconds
  - `:dpop_key` - pre-generated DPoP private JWK (default: a fresh P-256 key)
  """
  @spec authorize_url(Client.t(), Discovery.t(), keyword()) ::
          {:ok, {String.t(), RequestContext.t()}} | {:error, term()}
  def authorize_url(%Client{} = client, %Discovery{} = resolved, opts \\ []) do
    %ServerMetadata{} = auth_server = resolved.auth_server
    scope = ServerMetadata.supported_scopes(auth_server, opts[:scope] || client.metadata.scope)
    state = Keyword.get(opts, :state) || random_state()
    verifier = PKCE.generate_verifier()

    form = %{
      "client_id" => Client.client_id(client),
      "response_type" => "code",
      "redirect_uri" => client.redirect_uri,
      "scope" => Enum.join(scope, " "),
      "state" => state,
      "code_challenge" => PKCE.challenge(verifier),
      "code_challenge_method" => "S256",
      "login_hint" => resolved.did || resolved.handle
    }

    with {:ok, dpop_key} <- dpop_key(opts),
         :ok <- check_scope(scope),
         {:ok, request_uri} <-
           push_authorization_request(client, auth_server, form, dpop_key, opts) do
      authorize_url =
        auth_server.authorization_endpoint <>
          "?" <>
          URI.encode_query(%{
            "client_id" => Client.client_id(client),
            "request_uri" => request_uri
          })

      {:ok,
       {authorize_url,
        %RequestContext{
          state: state,
          verifier: verifier,
          redirect_uri: client.redirect_uri,
          dpop_key: dpop_key,
          client: client,
          auth_server: auth_server,
          expected_did: resolved.did,
          pds: resolved.pds
        }}}
    end
  end

  @doc """
  Complete the flow: validate the callback parameters and exchange the
  authorization code for a DPoP-bound session.

  `params` are the redirect query parameters (`"code"`, `"state"`, `"iss"`,
  or `"error"` / `"error_description"` on failure).
  """
  @spec callback(RequestContext.t(), map(), keyword()) :: {:ok, Session.t()} | {:error, term()}
  def callback(%RequestContext{} = ctx, params, opts \\ []) when is_map(params) do
    with :ok <- check_error(params),
         :ok <- check_state(ctx, params),
         :ok <- check_issuer(ctx, params),
         {:ok, code} <- require_param(params, "code") do
      exchange_code(ctx, code, opts)
    end
  end

  defp dpop_key(opts) do
    case Keyword.get(opts, :dpop_key) do
      nil -> DPoP.generate_key()
      key when is_map(key) -> {:ok, key}
      _ -> {:error, :invalid_dpop_key}
    end
  end

  defp check_scope([]), do: {:error, :no_supported_scopes}
  defp check_scope(_), do: :ok

  defp push_authorization_request(client, auth_server, form, dpop_key, opts) do
    form =
      form
      |> reject_nils()
      |> Map.merge(assertion_params(client, auth_server))

    case Request.authorized(
           opts[:http],
           :post,
           auth_server.pushed_authorization_request_endpoint,
           [form: form, timeout: opts[:timeout]],
           dpop_key,
           nil
         ) do
      {:ok, %{status: status, body: %{"request_uri" => request_uri}}}
      when status in [200, 201] and is_binary(request_uri) ->
        {:ok, request_uri}

      {:ok, %{status: status, body: body}} ->
        {:error, {:par_failed, status, body}}

      {:error, reason} ->
        {:error, {:par_failed, reason}}
    end
  end

  defp assertion_params(client, auth_server) do
    if Client.confidential?(client) do
      with {:ok, assertion} <- Client.assertion(client, auth_server.issuer) do
        %{"client_assertion_type" => @client_assertion_type, "client_assertion" => assertion}
      end
    else
      %{}
    end
  end

  defp exchange_code(%RequestContext{} = ctx, code, opts) do
    %ServerMetadata{} = auth_server = ctx.auth_server
    token_endpoint = auth_server.token_endpoint

    form =
      %{
        "grant_type" => "authorization_code",
        "code" => code,
        "code_verifier" => ctx.verifier,
        "redirect_uri" => ctx.redirect_uri,
        "client_id" => Client.client_id(ctx.client)
      }
      |> Map.merge(assertion_params(ctx.client, auth_server))

    with {:ok, %{status: 200, body: body}} when is_map(body) <-
           Request.authorized(
             opts[:http],
             :post,
             token_endpoint,
             [form: form, timeout: opts[:timeout]],
             ctx.dpop_key,
             nil
           ),
         :ok <- check_token_response(body) do
      Session.new(%{
        sub: body["sub"],
        access_token: body["access_token"],
        refresh_token: body["refresh_token"],
        scope: body["scope"],
        expires_in: body["expires_in"],
        dpop_key: ctx.dpop_key,
        client: ctx.client,
        auth_server: auth_server,
        expected_did: ctx.expected_did,
        pds: ctx.pds,
        http: opts[:http]
      })
    else
      {:ok, %{status: status, body: body}} ->
        {:error, {:token_exchange_failed, status, body}}

      {:error, _reason} = error ->
        error
    end
  end

  defp check_token_response(body) do
    validations = [
      require_field(body, "access_token"),
      require_field(body, "refresh_token"),
      require_field(body, "sub"),
      require_field(body, "scope"),
      check_token_type(body["token_type"]),
      check_atproto_scope(body["scope"])
    ]

    Enum.find(validations, &match?({:error, _}, &1)) || :ok
  end

  defp require_field(body, field) when is_map_key(body, field), do: :ok
  defp require_field(_body, field), do: {:error, {:missing_token_field, field}}

  defp check_token_type(type) when is_binary(type) do
    if String.downcase(type) == "dpop", do: :ok, else: {:error, :unsupported_token_type}
  end

  defp check_token_type(_), do: {:error, :unsupported_token_type}

  defp check_atproto_scope(scope) when is_binary(scope) do
    if "atproto" in String.split(scope), do: :ok, else: {:error, :atproto_scope_required}
  end

  defp check_atproto_scope(_), do: {:error, :atproto_scope_required}

  defp check_error(%{"error" => error}), do: {:error, {:authorization_failed, error}}

  defp check_error(%{"error_description" => desc}),
    do: {:error, {:authorization_failed, nil, desc}}

  defp check_error(_), do: :ok

  defp check_state(%RequestContext{state: expected}, %{"state" => state})
       when is_binary(state) and expected == state,
       do: :ok

  defp check_state(_ctx, %{"state" => _}), do: {:error, :state_mismatch}
  defp check_state(_ctx, _params), do: {:error, :missing_state}

  defp check_issuer(%RequestContext{auth_server: %{issuer: issuer}}, %{"iss" => iss})
       when is_binary(iss) do
    if DPoP.origin(iss) == DPoP.origin(issuer), do: :ok, else: {:error, :issuer_mismatch}
  end

  defp check_issuer(_ctx, _params), do: {:error, :missing_issuer}

  defp require_param(params, key) do
    case params do
      %{^key => value} when is_binary(value) and byte_size(value) > 0 -> {:ok, value}
      _ -> {:error, {:missing_param, key}}
    end
  end

  defp reject_nils(form), do: Map.reject(form, fn {_k, v} -> is_nil(v) end)

  defp random_state do
    32
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end
end
