defmodule Exosphere.ATProto.OAuth.ClientMetadata do
  @moduledoc """
  OAuth 2.0 Client Metadata Documents (the `client_id` document).

  In ATProto OAuth the `client_id` is a URL: the authorization server fetches
  the client metadata document from it. Web ("confidential") clients serve
  the document themselves and embed a public key (`jwks`), which authorizes
  them for `private_key_jwt` client authentication. Native/loopback clients
  instead use the special `http://localhost` client identifier built by
  `localhost_client_id/2` and skip the document entirely.

  Serve `to_document/1` as JSON at your `client_id` URL, and keep the
  matching private key secret — `Exosphere.ATProto.OAuth.Client` pairs the
  two at runtime.

  ## Examples

      iex> metadata = Exosphere.ATProto.OAuth.ClientMetadata.new!(
      ...>   client_id: "https://app.example.com/oauth-client-metadata.json",
      ...>   client_name: "My App",
      ...>   redirect_uris: ["https://app.example.com/oauth/callback"],
      ...>   scope: ["atproto", "transition:generic"],
      ...>   jwk: public_jwk
      ...> )
      iex> document = Exosphere.ATProto.OAuth.ClientMetadata.to_document(metadata)
  """

  alias Exosphere.ATProto.OAuth.JWK

  defstruct [
    :client_id,
    :client_name,
    :client_uri,
    :redirect_uris,
    :scope,
    :jwk,
    :logo_uri,
    :tos_uri,
    :policy_uri,
    application_type: :web,
    token_endpoint_auth_method: :private_key_jwt,
    dpop_bound_access_tokens: true,
    grant_types: [:authorization_code, :refresh_token],
    response_types: [:code],
    token_endpoint_auth_signing_alg: "ES256"
  ]

  @type t :: %__MODULE__{
          client_id: String.t(),
          client_name: String.t() | nil,
          client_uri: String.t() | nil,
          redirect_uris: [String.t()],
          scope: [String.t()],
          jwk: JWK.t() | nil,
          logo_uri: String.t() | nil,
          tos_uri: String.t() | nil,
          policy_uri: String.t() | nil,
          application_type: :web | :native,
          token_endpoint_auth_method: :private_key_jwt | :none,
          dpop_bound_access_tokens: boolean(),
          grant_types: [:authorization_code | :refresh_token],
          response_types: [:code],
          token_endpoint_auth_signing_alg: String.t()
        }

  @localhost_client_id "http://localhost"
  @default_scope ["atproto", "transition:generic"]

  @doc """
  Build and validate client metadata.

  ## Options

  - `:client_id` (required) - URL of the metadata document itself (https,
    or `http://localhost...` for local development)
  - `:redirect_uris` (required) - at least one https (or loopback) redirect URI
  - `:scope` - scope strings; must include `"atproto"`
    (default `#{inspect(@default_scope)}`)
  - `:jwk` - public JWK map for confidential clients (`private_key_jwt`);
    omit for public clients (which then use `token_endpoint_auth_method:
    :none`)
  - `:client_name`, `:client_uri`, `:logo_uri`, `:tos_uri`, `:policy_uri` -
    display metadata (all URIs must be https)
  - `:application_type` - `:web` (default) or `:native`
  - `:token_endpoint_auth_method` - inferred from `:jwk` presence when unset
  """
  @spec new(keyword()) :: {:ok, t()} | {:error, term()}
  def new(opts) do
    opts = Keyword.put_new(opts, :scope, @default_scope)

    with {:ok, client_id} <- require_url(Keyword.get(opts, :client_id), :client_id),
         {:ok, redirect_uris} <- redirect_uris(Keyword.fetch!(opts, :redirect_uris)),
         {:ok, auth_method} <- auth_method(opts),
         {:ok, scope} <- scope(Keyword.fetch!(opts, :scope)),
         :ok <- validate_display_uris(opts),
         :ok <- validate_application_type(opts) do
      {:ok,
       %__MODULE__{
         client_id: client_id,
         client_name: Keyword.get(opts, :client_name),
         client_uri: Keyword.get(opts, :client_uri),
         redirect_uris: redirect_uris,
         scope: scope,
         jwk: jwk_with_kid(Keyword.get(opts, :jwk)),
         logo_uri: Keyword.get(opts, :logo_uri),
         tos_uri: Keyword.get(opts, :tos_uri),
         policy_uri: Keyword.get(opts, :policy_uri),
         application_type: Keyword.get(opts, :application_type, :web),
         token_endpoint_auth_method: auth_method,
         grant_types: Keyword.get(opts, :grant_types, [:authorization_code, :refresh_token]),
         response_types: [:code],
         token_endpoint_auth_signing_alg: "ES256",
         dpop_bound_access_tokens: true
       }}
    end
  end

  @doc """
  Like `new/1`, but raises on invalid input.
  """
  @spec new!(keyword()) :: t()
  def new!(opts) do
    case new(opts) do
      {:ok, metadata} -> metadata
      {:error, reason} -> raise ArgumentError, "invalid client metadata: #{inspect(reason)}"
    end
  end

  @doc """
  Render the Client Metadata Document (`to_json`-ready map) served at
  `client_id`.
  """
  @spec to_document(t()) :: map()
  def to_document(%__MODULE__{} = metadata) do
    base = %{
      "client_id" => metadata.client_id,
      "application_type" => Atom.to_string(metadata.application_type),
      "grant_types" => Enum.map(metadata.grant_types, &Atom.to_string/1),
      "response_types" => ["code"],
      "redirect_uris" => metadata.redirect_uris,
      "scope" => Enum.join(metadata.scope, " "),
      "token_endpoint_auth_method" => Atom.to_string(metadata.token_endpoint_auth_method),
      "dpop_bound_access_tokens" => true
    }

    base
    |> maybe_put("client_name", metadata.client_name)
    |> maybe_put("client_uri", metadata.client_uri)
    |> maybe_put("logo_uri", metadata.logo_uri)
    |> maybe_put("tos_uri", metadata.tos_uri)
    |> maybe_put("policy_uri", metadata.policy_uri)
    |> confidential_fields(metadata)
  end

  @doc """
  The special loopback client identifier for local development:
  `http://localhost` with `redirect_uri` and `scope` query parameters, as
  allowed by the ATProto OAuth profile.

  The authorization server assembles a virtual metadata document from these
  parameters; no hosted document or client key is needed.
  """
  @spec localhost_client_id([String.t()], [String.t()]) ::
          {:ok, String.t()} | {:error, term()}
  def localhost_client_id(redirect_uris, scope \\ @default_scope)
      when is_list(redirect_uris) and is_list(scope) do
    with {:ok, redirect_uris} <- redirect_uris(redirect_uris),
         {:ok, scope} <- scope(scope),
         :ok <- check_loopback(redirect_uris) do
      query =
        URI.encode_query(%{
          "redirect_uri" => Enum.join(redirect_uris, " "),
          "scope" => Enum.join(scope, " ")
        })

      {:ok, @localhost_client_id <> "?" <> query}
    end
  end

  @doc """
  Whether this is a confidential client (uses `private_key_jwt` client
  authentication with a hosted key).
  """
  @spec confidential?(t()) :: boolean()
  def confidential?(%__MODULE__{token_endpoint_auth_method: :private_key_jwt}), do: true
  def confidential?(_), do: false

  defp confidential_fields(doc, %__MODULE__{jwk: nil}), do: doc

  defp confidential_fields(doc, %__MODULE__{jwk: jwk}) do
    Map.merge(doc, %{
      "token_endpoint_auth_signing_alg" => "ES256",
      "jwks" => %{"keys" => [jwk]}
    })
  end

  defp jwk_with_kid(nil), do: nil

  defp jwk_with_kid(jwk) do
    case JWK.thumbprint(jwk) do
      {:ok, thumbprint} -> Map.put_new(jwk, "kid", thumbprint)
      {:error, _reason} -> jwk
    end
  end

  defp redirect_uris([]), do: {:error, :redirect_uris_required}

  defp redirect_uris(uris) when is_list(uris) do
    if Enum.all?(uris, &https_or_loopback?/1) do
      {:ok, uris}
    else
      {:error, :invalid_redirect_uri}
    end
  end

  defp redirect_uris(_), do: {:error, :invalid_redirect_uris}

  defp check_loopback(uris) do
    if Enum.all?(uris, &loopback_url?(&1)) do
      :ok
    else
      {:error, :redirect_uri_not_loopback}
    end
  end

  defp auth_method(opts) do
    case Keyword.get(opts, :token_endpoint_auth_method) do
      nil ->
        if Keyword.get(opts, :jwk), do: {:ok, :private_key_jwt}, else: {:ok, :none}

      :private_key_jwt ->
        if Keyword.get(opts, :jwk),
          do: {:ok, :private_key_jwt},
          else: {:error, :jwk_required_for_confidential_client}

      :none ->
        if Keyword.get(opts, :jwk),
          do: {:error, :key_forbidden_for_public_client},
          else: {:ok, :none}

      _ ->
        {:error, :invalid_token_endpoint_auth_method}
    end
  end

  defp scope(scopes) when is_list(scopes) do
    if "atproto" in scopes, do: {:ok, scopes}, else: {:error, :atproto_scope_required}
  end

  defp scope(_), do: {:error, :invalid_scope}

  defp validate_display_uris(opts) do
    opts
    |> Keyword.take([:client_uri, :logo_uri, :tos_uri, :policy_uri])
    |> Enum.reduce_while(:ok, fn
      {_key, nil}, :ok -> {:cont, :ok}
      {key, uri}, :ok -> require_url(uri, key) |> cont_or_halt()
    end)
  end

  defp validate_application_type(opts) do
    case Keyword.get(opts, :application_type, :web) do
      type when type in [:web, :native] -> :ok
      _ -> {:error, :invalid_application_type}
    end
  end

  defp require_url(nil, key), do: {:error, {:missing, key}}

  defp require_url(url, key) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host}
      when scheme in ["https", "http"] and is_binary(host) ->
        if scheme == "http" and not loopback_url?(url) do
          {:error, {:not_https, key}}
        else
          {:ok, url}
        end

      _ ->
        {:error, {:invalid_url, key}}
    end
  end

  defp require_url(_, key), do: {:error, {:invalid_url, key}}

  defp https_or_loopback?(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: "https"} -> true
      _ -> loopback_url?(url)
    end
  end

  defp https_or_loopback?(_), do: false

  defp loopback_url?(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: "http", host: host} -> host in ["localhost", "127.0.0.1", "[::1]"]
      _ -> false
    end
  end

  defp loopback_url?(_), do: false

  defp cont_or_halt({:ok, _}), do: {:cont, :ok}
  defp cont_or_halt({:error, _} = error), do: {:halt, error}

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
