defmodule Exosphere.ATProto.XRPC.ServiceAuth do
  @moduledoc """
  Inter-service authentication JWTs (atproto XRPC spec, "Inter-Service
  Authentication (JWT)"): a short-lived token an account or service signs with
  its DID's signing key and sends as `Authorization: Bearer <jwt>`.

  The token's shape:

  | Part | Field | Value |
  |---|---|---|
  | header | `alg` | `ES256K` (secp256k1) or `ES256` (P-256), from the key |
  | header | `typ` | `JWT` |
  | header | `kid` | the verification method that signed it — `#atproto` by default |
  | payload | `iss` | the issuer's bare DID (no fragment: the key is named by `kid`) |
  | payload | `aud` | the recipient, as `did#serviceId` (a bare DID only where the recipient asks for one) |
  | payload | `lxm` | the NSID of the one method the token authorizes |
  | payload | `iat`, `exp` | seconds; 60-second lifetime by default |
  | payload | `jti` | a random nonce, so a recipient can refuse replays |

  `sign/2` mints one; `verify/3` checks one for a receiving service
  (signature, expiry, audience and method). Signing and verification use the
  same JWS machinery as the OAuth client and `Spaces.Token`, with keys as JWK
  maps (`Exosphere.ATProto.OAuth.JWK.from_keypair/2` converts an
  `ATProto.Crypto` keypair).

  The Spaces methods that use it: `com.atproto.space.unregisterNotify` (from
  the service being withdrawn), `notifyCredentialsRevoked` (from the space
  authority), `notifyRepoUpdate` / `notifySpaceStatus` (from repo and space
  hosts), and `com.atproto.managedspace.checkAccess` (from the authority).
  """

  alias Exosphere.ATProto.Identity.DID
  alias Exosphere.ATProto.NSID
  alias Exosphere.ATProto.OAuth.{JWK, JWS}

  @default_lifetime 60
  @default_kid "#atproto"
  @clock_skew_sec 5

  @type sign_opts :: [
          iss: String.t(),
          aud: String.t(),
          lxm: String.t(),
          kid: String.t(),
          expires_in: pos_integer(),
          iat: integer(),
          jti: String.t()
        ]

  @doc """
  Mint a service auth JWT signed with `private_jwk` (the issuer's signing key).

  Required: `:iss` (a bare DID — a fragment is refused, `{:error, :invalid_iss}`,
  since the key is named by `kid`), `:aud` (a DID, normally with its
  `#serviceId`), and `:lxm` (an NSID). Optional: `:kid` (default `"#atproto"`),
  `:expires_in` (seconds, default 60), and `:iat` / `:jti` to pin a token in
  tests.
  """
  @spec sign(sign_opts(), JWK.t()) :: {:ok, String.t()} | {:error, term()}
  def sign(opts, private_jwk) do
    opts = Map.new(opts)

    with {:ok, iss} <- fetch(opts, :iss, &bare_did?/1, :invalid_iss),
         {:ok, aud} <- fetch(opts, :aud, &did_ref?/1, :invalid_aud),
         {:ok, lxm} <- fetch(opts, :lxm, &NSID.valid?/1, :invalid_lxm),
         {:ok, alg} <- alg(private_jwk) do
      iat = Map.get(opts, :iat) || System.system_time(:second)
      expires_in = Map.get(opts, :expires_in, @default_lifetime)

      header = %{"typ" => "JWT", "alg" => alg, "kid" => Map.get(opts, :kid, @default_kid)}

      payload = %{
        "iss" => iss,
        "aud" => aud,
        "lxm" => lxm,
        "iat" => iat,
        "exp" => iat + expires_in,
        "jti" => Map.get(opts, :jti) || random_jti()
      }

      JWS.sign(private_jwk, header, payload)
    end
  end

  @doc """
  The request headers carrying a freshly minted token (`sign/2`):
  `[{"authorization", "Bearer " <> jwt}]`.
  """
  @spec headers(sign_opts(), JWK.t()) :: {:ok, [{String.t(), String.t()}]} | {:error, term()}
  def headers(opts, private_jwk) do
    with {:ok, jwt} <- sign(opts, private_jwk), do: {:ok, [{"authorization", "Bearer " <> jwt}]}
  end

  @doc """
  Verify a service auth JWT as its recipient.

  `get_signing_key` receives `(iss, kid, force_refresh)` and returns the
  issuer's public JWK for that verification method (normally `#atproto`
  from its DID document); on a signature failure it is asked once more with
  `force_refresh: true`, for a key that rotated since it was cached.

  Options:

  - `:aud` (required) — the audience this service answers to; a string, or a
    list of acceptable values (e.g. `["did:web:x#atproto_pds", "did:web:x"]`).
  - `:lxm` (required) — the NSID of the method being called; a token for any
    other method, or none, is refused.
  - `:now` — the current time in seconds, for tests.

  Returns `{:ok, payload}`. Refusals: `:invalid_token`, `:token_expired`,
  `:bad_audience`, `:bad_lxm`, `:invalid_iss`, `:signing_key_unavailable`,
  `:invalid_signature`. Replay protection (remembering `jti`s until `exp`) is
  the recipient's.
  """
  @spec verify(
          String.t(),
          (String.t(), String.t() | nil, boolean() ->
             {:ok, JWK.t()} | {:error, term()}),
          keyword()
        ) ::
          {:ok, map()} | {:error, term()}
  def verify(jwt, get_signing_key, opts)
      when is_binary(jwt) and is_function(get_signing_key, 3) do
    auds = opts |> Keyword.fetch!(:aud) |> List.wrap()
    lxm = Keyword.fetch!(opts, :lxm)
    now = Keyword.get(opts, :now) || System.system_time(:second)

    with {:ok, header, payload} <- JWS.decode(jwt),
         :ok <- check_typ(header),
         {:ok, iss} <- payload_iss(payload),
         :ok <- check_exp(payload, now),
         :ok <- if(payload["aud"] in auds, do: :ok, else: {:error, :bad_audience}),
         :ok <- if(payload["lxm"] == lxm, do: :ok, else: {:error, :bad_lxm}),
         :ok <- check_signature(jwt, iss, header["kid"], get_signing_key) do
      {:ok, payload}
    end
  end

  def verify(_, _, _), do: {:error, :invalid_token}

  # -- signing ---------------------------------------------------------------

  defp fetch(opts, key, valid?, error) do
    case Map.fetch(opts, key) do
      {:ok, value} when is_binary(value) ->
        if valid?.(value), do: {:ok, value}, else: {:error, error}

      _ ->
        {:error, error}
    end
  end

  defp bare_did?(value), do: not String.contains?(value, "#") and DID.valid?(value)

  defp did_ref?(value) do
    case String.split(value, "#", parts: 2) do
      [did] -> DID.valid?(did)
      [did, service_id] -> service_id != "" and DID.valid?(did)
    end
  end

  defp alg(%{"crv" => "P-256"}), do: {:ok, "ES256"}
  defp alg(%{"crv" => "secp256k1"}), do: {:ok, "ES256K"}
  defp alg(_), do: {:error, :unsupported_key}

  defp random_jti, do: :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)

  # -- verification ----------------------------------------------------------

  # The spec leaves `typ` open ("currently JWT"); like the reference, refuse
  # the token types that are known not to be service auth.
  defp check_typ(%{"typ" => typ}) when typ in ["at+jwt", "refresh+jwt", "dpop+jwt"],
    do: {:error, :invalid_token}

  defp check_typ(%{"alg" => alg}) when alg in ["ES256", "ES256K"], do: :ok
  defp check_typ(_), do: {:error, :invalid_token}

  defp payload_iss(%{"iss" => iss}) when is_binary(iss) do
    if did_ref?(iss), do: {:ok, iss}, else: {:error, :invalid_iss}
  end

  defp payload_iss(_), do: {:error, :invalid_iss}

  defp check_exp(%{"exp" => exp}, now) when is_integer(exp) do
    if now - @clock_skew_sec >= exp, do: {:error, :token_expired}, else: :ok
  end

  defp check_exp(_, _), do: {:error, :invalid_token}

  defp check_signature(jwt, iss, kid, get_key) do
    with {:ok, key} <- fetch_key(get_key, iss, kid, false) do
      case verify_with(key, jwt) do
        :ok ->
          :ok

        :error ->
          with {:ok, fresh} <- fetch_key(get_key, iss, kid, true),
               :ok <- verify_with(fresh, jwt) do
            :ok
          else
            {:error, _} = error -> error
            :error -> {:error, :invalid_signature}
          end
      end
    end
  end

  defp verify_with(key, jwt) do
    with {:ok, alg} <- alg(key),
         {:ok, _} <- JWS.verify(key, jwt, [alg]) do
      :ok
    else
      _ -> :error
    end
  end

  defp fetch_key(get_key, iss, kid, force_refresh) do
    case get_key.(iss, kid, force_refresh) do
      {:ok, %{} = jwk} -> {:ok, jwk}
      _ -> {:error, :signing_key_unavailable}
    end
  end
end
