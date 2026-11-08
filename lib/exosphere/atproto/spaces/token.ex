defmodule Exosphere.ATProto.Spaces.Token do
  @moduledoc """
  The three space token classes of atproto permissioned data (proposal 0016),
  sharing one wire shape — a compact JWS — and differing only in who signs
  them, who they are addressed to, and how long they live. Every class
  carries a `jti` (the credential's is what `notifyCredentialRevoked` names):

  | Class | typ | signed by | TTL | aud | binding |
  |-------|-----|-----------|-----|-----|---------|
  | `:delegation` | `atproto-space-delegation+jwt` | the user's PDS (`#atproto` key) | 60s, single-use | required (the space host) | — |
  | `:credential` | `atproto-space-credential+jwt` | the space authority (`#atproto` key) | 600s (at most 3600s), multi-use | none (it is presented to every repo host in the space) | a P-256 `did:key` via `cnf.kid` |
  | `:client_attestation` | `atproto-client-attestation+jwt` | the app's client-authentication key | 60s, single-use | required (the space host) | — |

  ## Credentials bind a key, not a DPoP thumbprint

  Since atproto `b34848587`/`94de8ab02` a credential is bound to a P-256
  `did:key` the syncer generated (`cnf.kid`), and every request presenting it
  carries an HTTP Message Signature by that key
  (`Spaces.HttpSignature`). It lives 600 seconds by default; `sign/3` refuses
  a lifetime over 3600 seconds and `parse/2` rejects one (`:invalid_lifetime`),
  as the reference verifier does, and `verify/3` rejects a credential issued
  in the future beyond the clock skew (`:issued_in_future`).

  ## The `kid` is fixed for user and authority tokens

  Delegation tokens and space credentials are signed with the issuer's
  account signing key and carry `kid: "#atproto"` — exactly that string.
  Until atproto `432ef66` (2026-10-20) an authority could sign credentials
  with a dedicated `#atproto_space` key and say so in the `kid`; upstream
  dropped that key, and the reference verifier now rejects any other `kid`.
  So does this module: `sign/3` refuses a `:kid` option for those two classes
  (`{:error, :fixed_kid}`), and `parse/2` refuses a header whose `kid` is not
  `"#atproto"` (`{:error, :invalid_kid}`).

  Client attestations are the exception: their `kid` names a key in the
  client's published JWKS, and is the caller's to pass (or omit).

  Signing and verification go through the OAuth client's JWS machinery
  (`Exosphere.ATProto.OAuth.JWS`, built for `private_key_jwt` client
  assertions) with keys as JWK maps (`Exosphere.ATProto.OAuth.JWK`) —
  `ES256K` for secp256k1 account keys, `ES256` for P-256 app keys.

  `parse/2` is structural only — it never checks a signature. `verify/3` adds
  expiry (with clock skew), audience/subject, and signature checks, resolving
  the signing key through a callback so hosts can plug in their own (possibly
  cached, possibly rotating) key source.
  """

  alias Exosphere.ATProto.OAuth.{JWK, JWS}
  alias Exosphere.ATProto.Spaces.HttpSignature

  @clock_skew_sec 5

  @type class :: :delegation | :credential | :client_attestation
  @type private_jwk :: JWK.t()
  @type public_jwk :: JWK.t()

  @type sign_opts :: [
          iss: String.t(),
          sub: String.t(),
          aud: String.t() | nil,
          key_id: String.t() | nil,
          expires_in: pos_integer(),
          kid: String.t() | nil,
          jti: String.t(),
          iat: integer()
        ]

  @type get_signing_key ::
          (iss :: String.t(), kid :: String.t() | nil, force_refresh :: boolean() ->
             {:ok, public_jwk()} | {:error, term()})

  @type verify_opts :: [
          get_signing_key: get_signing_key(),
          aud: String.t() | nil,
          sub: String.t() | nil,
          now: integer()
        ]

  # The token classes as data: who they're addressed to, how they bind, and
  # how long they live.
  @classes %{
    delegation: %{
      typ: "atproto-space-delegation+jwt",
      kid: "#atproto",
      expires_in: 60,
      require_aud: true,
      require_cnf: false,
      single_use: true
    },
    credential: %{
      typ: "atproto-space-credential+jwt",
      kid: "#atproto",
      expires_in: 600,
      require_aud: false,
      require_cnf: true,
      single_use: false
    },
    client_attestation: %{
      typ: "atproto-client-attestation+jwt",
      kid: nil,
      expires_in: 60,
      require_aud: true,
      require_cnf: false,
      single_use: true
    }
  }

  @doc """
  How a space authority is addressed as the audience of a delegation token or
  client attestation: the authority DID plus its PDS service fragment. The
  space host is the authority's PDS, like any other atproto account.

  This was `#atproto_space_host` until atproto `432ef66` (2026-10-20); a
  current host refuses a token addressed to the old fragment.
  """
  @spec space_host_aud(String.t()) :: String.t()
  def space_host_aud(space_did), do: space_did <> "#atproto_pds"

  @doc """
  Sign a space token of `class` with a private JWK.

  `:iss` and `:sub` are required; `:aud` is required for classes addressed to
  a space host; `:key_id` is required for credentials (the P-256 `did:key`
  the credential binds to, from the `credentialKid` the requester sent).
  `:iat`, `:jti`, and `:expires_in` may be pinned for tests; a credential's
  `:expires_in` must be within (0, 3600].

  `:kid` is accepted for client attestations only (the JWKS key id, omitted
  when not given); delegation tokens and credentials always carry
  `"#atproto"` and refuse the option with `{:error, :fixed_kid}` — see "The
  `kid` is fixed for user and authority tokens" above.
  """
  @spec sign(class(), sign_opts(), private_jwk()) :: {:ok, binary()} | {:error, term()}
  def sign(class, opts, private_jwk) when is_map_key(@classes, class) do
    spec = @classes[class]
    opts = Map.new(opts)

    with :ok <- check_kid_opt(opts, spec.kid),
         :ok <- require_opt(opts, :aud, spec.require_aud, :missing_aud),
         :ok <- require_opt(opts, :key_id, spec.require_cnf, :missing_cnf),
         :ok <- check_key_id(opts, spec.require_cnf),
         :ok <- check_lifetime_opt(class, Map.get(opts, :expires_in, spec.expires_in)),
         :ok <- require_opt(opts, :iss, true, :missing_iss),
         :ok <- require_opt(opts, :sub, true, :missing_sub) do
      iat = Map.get(opts, :iat) || System.system_time(:second)
      expires_in = Map.get(opts, :expires_in, spec.expires_in)

      header =
        %{"typ" => spec.typ, "alg" => alg(private_jwk)}
        |> maybe_put("kid", spec.kid || Map.get(opts, :kid))

      payload =
        %{
          "iss" => opts.iss,
          "sub" => opts.sub,
          "iat" => iat,
          "exp" => iat + expires_in,
          "jti" => Map.get(opts, :jti) || random_jti()
        }
        |> maybe_put("aud", Map.get(opts, :aud))
        |> maybe_put("cnf", kid_cnf(Map.get(opts, :key_id)))

      JWS.sign(private_jwk, header, payload)
    end
  end

  def sign(_, _, _), do: {:error, :unknown_token_class}

  @doc """
  Structurally parse a space token of `class` — shape and `typ` only, no
  signature check. (This is as far as client attestations go on their own:
  their signing key comes from the client's JWKS, not a DID document.)
  """
  @spec parse(class(), binary()) ::
          {:ok, %{header: map(), payload: map(), jwt: binary()}} | {:error, term()}
  def parse(class, jwt) when is_binary(jwt) and is_map_key(@classes, class) do
    spec = @classes[class]

    with {:ok, header, payload} <- JWS.decode(jwt),
         :ok <- check_typ(header, spec.typ),
         :ok <- check_alg(header),
         :ok <- check_kid(header, spec.kid) do
      with :ok <- required_string(payload, "iss", :missing_iss),
           :ok <- required_string(payload, "sub", :missing_sub),
           :ok <- required_int(payload, "exp", :missing_exp),
           :ok <- required_if(payload, "aud", spec.require_aud, :missing_aud),
           :ok <- required_cnf(payload, spec.require_cnf),
           :ok <- required_string(payload, "jti", :missing_jti),
           :ok <- check_lifetime(class, payload),
           :ok <- attestation_subject(class, payload) do
        {:ok, %{header: header, payload: payload, jwt: jwt}}
      end
    else
      {:error, _} = error -> error
    end
  end

  def parse(class, _) when is_map_key(@classes, class), do: {:error, :invalid_token}
  def parse(_, _), do: {:error, :unknown_token_class}

  @doc """
  Verify a space token of `class`: structure, expiry (with clock-skew
  allowance), the optional `:aud`/`:sub` expectations, and the signature.

  `:get_signing_key` receives `(iss, kid, force_refresh)` and returns the
  signer's public JWK. On a failed signature the key is fetched once more
  with `force_refresh: true`, so a rotation since the cached key was stored
  doesn't reject a valid token.
  """
  @spec verify(class(), binary(), verify_opts()) :: {:ok, map()} | {:error, term()}
  def verify(class, jwt, opts \\ [])

  def verify(class, jwt, opts) when is_map_key(@classes, class) do
    get_key = Keyword.fetch!(opts, :get_signing_key)
    now = Keyword.get(opts, :now) || System.system_time(:second)

    with {:ok, %{header: header, payload: payload}} <- parse(class, jwt),
         :ok <- check_exp(payload, now),
         :ok <- check_iat(class, payload, now),
         :ok <- check_aud(payload, Keyword.get(opts, :aud)),
         :ok <- check_sub(payload, Keyword.get(opts, :sub)),
         {:ok, key} <- fetch_key(get_key, payload["iss"], header["kid"], false),
         :ok <- maybe_signature(jwt, payload["iss"], header["kid"], key, get_key) do
      {:ok, %{header: header, payload: payload}}
    end
  end

  def verify(_, _, _), do: {:error, :unknown_token_class}

  defp maybe_signature(jwt, iss, kid, key, get_key) do
    # The alg restriction (RFC 8725) comes from the key's own curve.
    case JWS.verify(key, jwt, [alg(key)]) do
      {:ok, _} ->
        :ok

      {:error, _} ->
        # The signing key may have rotated since the cached one was fetched.
        with {:ok, fresh} <- fetch_key(get_key, iss, kid, true),
             {:ok, _} <- JWS.verify(fresh, jwt, [alg(fresh)]) do
          :ok
        else
          _ -> {:error, :invalid_signature}
        end
    end
  end

  defp alg(%{"crv" => "P-256"}), do: "ES256"
  defp alg(%{"crv" => "secp256k1"}), do: "ES256K"
  defp alg(_), do: "unsupported_alg"

  defp fetch_key(get_key, iss, kid, force_refresh) do
    case get_key.(iss, kid, force_refresh) do
      {:ok, %{} = jwk} -> {:ok, jwk}
      _ -> {:error, :signing_key_unavailable}
    end
  end

  defp check_exp(%{"exp" => exp}, now) when is_integer(exp) do
    if now - @clock_skew_sec >= exp, do: {:error, :token_expired}, else: :ok
  end

  defp check_aud(%{"aud" => aud}, nil) when is_binary(aud), do: :ok
  defp check_aud(%{"aud" => aud}, expected) when aud == expected, do: :ok

  defp check_aud(%{"aud" => aud}, expected) when is_binary(aud) and is_binary(expected),
    do: {:error, :bad_audience}

  defp check_aud(_, nil), do: :ok
  defp check_aud(_, _), do: {:error, :bad_audience}

  defp check_sub(%{"sub" => sub}, nil) when is_binary(sub), do: :ok
  defp check_sub(%{"sub" => sub}, expected) when sub == expected, do: :ok

  defp check_sub(%{"sub" => sub}, expected) when is_binary(sub) and is_binary(expected),
    do: {:error, :bad_subject}

  defp check_sub(_, nil), do: :ok
  defp check_sub(_, _), do: {:error, :bad_subject}

  defp attestation_subject(:client_attestation, %{"iss" => iss, "sub" => sub}) do
    if iss == sub, do: :ok, else: {:error, :attestation_subject}
  end

  defp attestation_subject(_, _), do: :ok

  # A class with a fixed kid (delegation, credential) carries exactly it.
  defp check_kid(_header, nil), do: :ok
  defp check_kid(%{"kid" => kid}, expected) when kid == expected, do: :ok
  defp check_kid(_header, _expected), do: {:error, :invalid_kid}

  defp check_kid_opt(opts, nil) when is_map(opts), do: :ok
  defp check_kid_opt(opts, _fixed) when is_map_key(opts, :kid), do: {:error, :fixed_kid}
  defp check_kid_opt(_opts, _fixed), do: :ok

  defp check_typ(%{"typ" => typ}, expected) when typ == expected, do: :ok
  defp check_typ(_, _), do: {:error, :wrong_token_type}

  defp check_alg(%{"alg" => alg}) when alg in ["ES256", "ES256K"], do: :ok
  defp check_alg(_), do: {:error, :invalid_token}

  defp required_string(payload, key, error) do
    if is_binary(payload[key]) and payload[key] != "", do: :ok, else: {:error, error}
  end

  defp required_int(payload, key, error) do
    if is_integer(payload[key]), do: :ok, else: {:error, error}
  end

  defp required_if(_payload, _key, false, _error), do: :ok

  defp required_if(payload, key, true, error), do: required_string(payload, key, error)

  defp required_cnf(payload, false) when is_map_key(payload, "cnf"), do: :ok
  defp required_cnf(_payload, false), do: :ok

  defp required_cnf(%{"cnf" => %{"kid" => "did:" <> _}}, true), do: :ok
  defp required_cnf(_, true), do: {:error, :missing_cnf}

  defp require_opt(opts, key, required?, error) do
    present? = match?(%{^key => v} when is_binary(v) and v != "", opts)

    cond do
      present? -> :ok
      required? -> {:error, error}
      true -> :ok
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp random_jti, do: :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)

  defp kid_cnf(nil), do: nil
  defp kid_cnf(key_id), do: %{"kid" => key_id}

  # The reference's SPACE_CREDENTIAL_MAX_AGE_SEC: a credential living longer
  # than an hour is refused at mint time and at verification.
  @max_credential_lifetime 3600

  defp check_key_id(%{key_id: key_id}, true) do
    if HttpSignature.p256_did_key?(key_id), do: :ok, else: {:error, :invalid_key_id}
  end

  defp check_key_id(_opts, _required), do: :ok

  defp check_lifetime_opt(:credential, expires_in)
       when is_integer(expires_in) and expires_in > 0 and expires_in <= @max_credential_lifetime,
       do: :ok

  defp check_lifetime_opt(:credential, _), do: {:error, :invalid_lifetime}
  defp check_lifetime_opt(_class, _), do: :ok

  defp check_lifetime(:credential, %{"iat" => iat, "exp" => exp})
       when is_integer(iat) and is_integer(exp) and exp > iat and
              exp - iat <= @max_credential_lifetime,
       do: :ok

  defp check_lifetime(:credential, _), do: {:error, :invalid_lifetime}
  defp check_lifetime(_class, _payload), do: :ok

  defp check_iat(:credential, %{"iat" => iat}, now) do
    if iat > now + @clock_skew_sec, do: {:error, :issued_in_future}, else: :ok
  end

  defp check_iat(_class, _payload, _now), do: :ok
end
