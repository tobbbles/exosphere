defmodule Exosphere.ATProto.Spaces.Token do
  @moduledoc """
  The three space token classes of atproto permissioned data (proposal 0016),
  sharing one wire shape — a compact JWS — and differing only in who signs
  them, who they are addressed to, and how long they live:

  | Class | typ | signed by | TTL | aud | binding |
  |-------|-----|-----------|-----|-----|---------|
  | `:delegation` | `atproto-space-delegation+jwt` | the user's PDS (`#atproto` key) | 60s, single-use | required (the space host) | — |
  | `:credential` | `atproto-space-credential+jwt` | the space authority (`#atproto` by default — see below) | 2h, multi-use | none (it is presented to every repo host in the space) | DPoP key via `cnf.jkt` |
  | `:client_attestation` | `atproto-client-attestation+jwt` | the app's client-authentication key | 60s, single-use | required (the space host) | — |

  ## The `kid` is a default, not a constant

  The key ids above are what `sign/3` stamps when the caller says nothing.
  They are not a property of the token class, and `sign/3` does not inspect
  the key it was handed: **a header's `kid` must name the fragment its signing
  key was actually published under**, because a verifier that honours `kid`
  resolves that verification method and nothing else.

  `#atproto` is the credential default because a space authority's signing key
  usually *is* the account's `#atproto` key — the case for any authority
  hosted on a PDS, and what the reference implementation does. `#atproto_space`
  is an optional, space-tokens-only verification method; an authority that
  publishes one and signs with it must say so:

      Token.sign(:credential, [iss: authority, sub: space, dpop_jkt: jkt,
                               kid: "#atproto_space"], space_jwk)

  Getting this wrong is invisible against a verifier that ignores `kid` (as
  passing `fn _iss, _kid, _refresh -> ... end` does) and fails against one
  that does not.

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

  @clock_skew_sec 5

  @type class :: :delegation | :credential | :client_attestation
  @type private_jwk :: JWK.t()
  @type public_jwk :: JWK.t()

  @type sign_opts :: [
          iss: String.t(),
          sub: String.t(),
          aud: String.t() | nil,
          dpop_jkt: String.t() | nil,
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
    # An authority that publishes a dedicated `#atproto_space` key signs with
    # it and passes that `kid`. Absent one, the space signing key is the
    # account's `#atproto` key — the case for any authority on a PDS.
    credential: %{
      typ: "atproto-space-credential+jwt",
      kid: "#atproto",
      expires_in: 7200,
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
  client attestation: the authority DID plus the space-host service fragment.
  This names the *audience*, not necessarily where requests are sent.
  """
  @spec space_host_aud(String.t()) :: String.t()
  def space_host_aud(space_did), do: space_did <> "#atproto_space_host"

  @doc """
  Sign a space token of `class` with a private JWK.

  `:iss` and `:sub` are required; `:aud` is required for classes addressed to
  a space host; `:dpop_jkt` is required for credentials (the RFC 7638
  thumbprint of the DPoP key the credential binds to). `:iat`, `:jti`, and
  `:expires_in` may be pinned for tests.

  `:kid` overrides the class default, and must be passed whenever
  `private_jwk` was published under some other fragment — see "The `kid` is a
  default, not a constant" above. `kid: nil` omits the header entirely.
  """
  @spec sign(class(), sign_opts(), private_jwk()) :: {:ok, binary()} | {:error, term()}
  def sign(class, opts, private_jwk) when is_map_key(@classes, class) do
    spec = @classes[class]
    opts = Map.new(opts)

    with :ok <- require_opt(opts, :aud, spec.require_aud, :missing_aud),
         :ok <- require_opt(opts, :dpop_jkt, spec.require_cnf, :missing_cnf),
         :ok <- require_opt(opts, :iss, true, :missing_iss),
         :ok <- require_opt(opts, :sub, true, :missing_sub) do
      iat = Map.get(opts, :iat) || System.system_time(:second)
      expires_in = Map.get(opts, :expires_in, spec.expires_in)

      header =
        %{"typ" => spec.typ, "alg" => alg(private_jwk)}
        |> maybe_put("kid", Map.get(opts, :kid, spec.kid))

      payload =
        %{
          "iss" => opts.iss,
          "sub" => opts.sub,
          "iat" => iat,
          "exp" => iat + expires_in,
          "jti" => Map.get(opts, :jti) || random_jti()
        }
        |> maybe_put("aud", Map.get(opts, :aud))
        |> maybe_put("cnf", jkt_cnf(Map.get(opts, :dpop_jkt)))

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
         :ok <- check_alg(header) do
      with :ok <- required_string(payload, "iss", :missing_iss),
           :ok <- required_string(payload, "sub", :missing_sub),
           :ok <- required_int(payload, "exp", :missing_exp),
           :ok <- required_if(payload, "aud", spec.require_aud, :missing_aud),
           :ok <- required_cnf(payload, spec.require_cnf),
           :ok <- required_if(payload, "jti", spec.single_use, :missing_jti),
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

  defp required_cnf(%{"cnf" => %{"jkt" => jkt}}, true) when is_binary(jkt) and jkt != "", do: :ok
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

  defp jkt_cnf(nil), do: nil
  defp jkt_cnf(jkt), do: %{"jkt" => jkt}
end
