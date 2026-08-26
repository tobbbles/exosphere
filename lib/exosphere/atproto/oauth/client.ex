defmodule Exosphere.ATProto.OAuth.Client do
  @moduledoc """
  Runtime OAuth client configuration: the metadata document paired with the
  private client-authentication key.

  Confidential clients keep a long-lived ES256 key; the matching public JWK
  is published in the client metadata document (`jwks`), and the private key
  signs the `private_key_jwt` client assertions used at the PAR and token
  endpoints. Public clients (e.g. loopback development clients) carry no key
  and authenticate with PKCE alone.
  """

  alias Exosphere.ATProto.OAuth.{ClientMetadata, JWK, JWS}

  defstruct [:metadata, :key, :redirect_uri]

  @type t :: %__MODULE__{
          metadata: ClientMetadata.t(),
          key: map() | nil,
          redirect_uri: String.t()
        }

  @assertion_ttl 300

  @doc """
  Build a client.

  ## Options

  - `:metadata` (required) - `ClientMetadata.t()`
  - `:key` - private JWK map; required for confidential clients, forbidden
    for public ones
  - `:redirect_uri` (required) - one of `metadata.redirect_uris`
  """
  @spec new(keyword()) :: {:ok, t()} | {:error, term()}
  def new(opts) do
    metadata = Keyword.get(opts, :metadata)
    key = Keyword.get(opts, :key)
    redirect_uri = Keyword.get(opts, :redirect_uri)

    with %ClientMetadata{} <- metadata || {:error, :metadata_required},
         true <- is_binary(redirect_uri) || {:error, :redirect_uri_required},
         true <- redirect_uri in metadata.redirect_uris || {:error, :redirect_uri_not_registered},
         :ok <- check_key(metadata, key) do
      {:ok, %__MODULE__{metadata: metadata, key: key, redirect_uri: redirect_uri}}
    else
      {:error, _} = error -> error
    end
  end

  @doc """
  Like `new/1`, but raises on invalid input.
  """
  @spec new!(keyword()) :: t()
  def new!(opts) do
    case new(opts) do
      {:ok, client} -> client
      {:error, reason} -> raise ArgumentError, "invalid OAuth client: #{inspect(reason)}"
    end
  end

  @doc """
  The client identifier (`client_id` URL).
  """
  @spec client_id(t()) :: String.t()
  def client_id(%__MODULE__{metadata: %ClientMetadata{client_id: id}}), do: id

  @doc """
  Whether the client authenticates with `private_key_jwt`.
  """
  @spec confidential?(t()) :: boolean()
  def confidential?(%__MODULE__{metadata: metadata}), do: ClientMetadata.confidential?(metadata)

  @doc """
  Mint a `private_key_jwt` client assertion (RFC 7523) for an authorization
  server: `iss`/`sub` are the `client_id`, `aud` is the server issuer.

  ## Options

  - `:iat` - issuance time in seconds (defaults to now); for tests
  """
  @spec assertion(t(), String.t(), keyword()) :: {:ok, binary()} | {:error, term()}
  def assertion(client, issuer, opts \\ [])

  def assertion(%__MODULE__{key: nil}, _issuer, _opts), do: {:error, :public_client}

  def assertion(%__MODULE__{} = client, issuer, opts) do
    now = Keyword.get(opts, :iat, System.system_time(:second))

    claims = %{
      "iss" => client_id(client),
      "sub" => client_id(client),
      "aud" => issuer,
      "jti" => jti(),
      "iat" => now,
      "exp" => now + @assertion_ttl
    }

    JWS.sign(client.key, assertion_headers(client.key), claims)
  end

  # The atproto OAuth profile requires `kid` on the assertion header so the
  # authorization server can pick the verification key from the client's
  # published `jwks` — the RFC 7638 thumbprint `ClientMetadata` publishes.
  # bsky.social rejects the assertion outright without it ("kid required in
  # client_assertion").
  defp assertion_headers(key) do
    header = %{"alg" => "ES256", "typ" => "JWT"}

    kid =
      case key do
        %{"kid" => kid} when is_binary(kid) -> {:ok, kid}
        key -> JWK.thumbprint(key)
      end

    case kid do
      {:ok, kid} -> Map.put(header, "kid", kid)
      {:error, _reason} -> header
    end
  end

  @doc """
  The client as a plain, `Jason`-encodable map for persistence.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = client) do
    %{
      "metadata" => Map.from_struct(client.metadata),
      "key" => client.key,
      "redirect_uri" => client.redirect_uri
    }
  end

  @doc """
  Rebuild a client serialized with `to_map/1`.

  Enum fields may have become strings through a JSON round-trip; they are
  normalized back to atoms.
  """
  @spec from_map(map()) :: {:ok, t()} | {:error, :invalid_client}
  def from_map(%{"metadata" => raw, "redirect_uri" => redirect_uri} = map)
      when is_map(raw) do
    base = Map.new(raw, fn {k, v} -> {String.to_atom(k), v} end)
    metadata = struct!(ClientMetadata, base)

    metadata = %{
      metadata
      | application_type: atomize(Map.get(base, :application_type), :web),
        token_endpoint_auth_method: atomize(Map.get(base, :token_endpoint_auth_method), :none),
        grant_types: base |> Map.get(:grant_types, []) |> Enum.map(&atomize(&1, :code)),
        response_types: base |> Map.get(:response_types, []) |> Enum.map(&atomize(&1, :code))
    }

    {:ok, %__MODULE__{metadata: metadata, key: map["key"], redirect_uri: redirect_uri}}
  rescue
    _ -> {:error, :invalid_client}
  end

  def from_map(_), do: {:error, :invalid_client}

  defp atomize(value, _default) when is_atom(value), do: value
  defp atomize(value, _default) when is_binary(value), do: String.to_atom(value)
  defp atomize(_value, default), do: default

  defp check_key(metadata, nil) do
    if ClientMetadata.confidential?(metadata),
      do: {:error, :key_required_for_confidential_client},
      else: :ok
  end

  defp check_key(metadata, key) when is_map(key) and is_map_key(key, "d") do
    if ClientMetadata.confidential?(metadata),
      do: :ok,
      else: {:error, :key_forbidden_for_public_client}
  end

  defp check_key(_metadata, _key), do: {:error, :invalid_client_key}

  defp jti do
    16
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end
end
