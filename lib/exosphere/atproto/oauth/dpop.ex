defmodule Exosphere.ATProto.OAuth.DPoP do
  @moduledoc """
  DPoP (RFC 9449) proof JWTs for the ATProto OAuth profile.

  Every request an ATProto OAuth client makes — the PAR request, the token
  requests, and each resource (XRPC) request — carries a fresh proof JWT in a
  `DPoP` header, signed by the session's DPoP key, binding the request's
  method and URI (and, for resource requests, the access token via `ath`).

  Servers may require a server-issued nonce (`400` with `use_dpop_nonce` and
  a `DPoP-Nonce` response header); `Exosphere.ATProto.OAuth.Request` handles
  the retry loop, backed by `Exosphere.ATProto.OAuth.DPoP.NonceStore`.

  ## Examples

      {:ok, key} = Exosphere.ATProto.OAuth.DPoP.generate_key()
      proof = Exosphere.ATProto.OAuth.DPoP.proof(key, "POST", "https://pds.example.com/xrpc/com.atproto.repo.describeRepo",
        ath: "eyJ...")
  """

  alias Exosphere.ATProto.OAuth.{JWK, JWS}

  @type private_key :: JWK.t()

  @doc """
  Generate a fresh P-256 DPoP keypair as a private JWK map.

  ATProto clients generate a new DPoP key per user/device/session, starting
  with the PAR request.
  """
  @spec generate_key() :: {:ok, private_key()}
  def generate_key do
    JWK.generate(:p256)
  end

  @doc """
  Mint a DPoP proof JWT for a request.

  ## Options

  - `:nonce` - server-issued nonce (required when the server has issued one)
  - `:ath` - access token; when present, its SHA-256 hash is bound into the
    proof as `ath` (resource-server requests)
  - `:iat` - issuance time in seconds (defaults to now); for tests
  """
  @spec proof(private_key(), String.t(), String.t(), keyword()) ::
          {:ok, binary()} | {:error, term()}
  def proof(private_key, htm, htu, opts \\ []) do
    claims = %{
      "jti" => jti(),
      "htm" => htm,
      "htu" => normalize_htu(htu),
      "iat" => Keyword.get(opts, :iat, System.system_time(:second))
    }

    claims =
      claims
      |> maybe_put("nonce", Keyword.get(opts, :nonce))
      |> maybe_put("ath", ath(Keyword.get(opts, :ath)))

    header = %{
      "typ" => "dpop+jwt",
      "alg" => alg(private_key),
      "jwk" => JWK.to_public(private_key)
    }

    JWS.sign(private_key, header, claims)
  end

  @doc """
  Normalize a URL into an `htu` per RFC 9449 §4.3: scheme and host
  lowercased, default ports dropped (non-default ports kept), path retained
  (empty becomes `/`), query and fragment stripped.
  """
  @spec normalize_htu(String.t()) :: String.t()
  def normalize_htu(url) when is_binary(url) do
    %URI{} = parsed = URI.parse(url)
    "#{base(parsed)}#{path(parsed)}"
  end

  @proof_typ "dpop+jwt"
  @proof_alg "ES256"
  @proof_max_age_sec 60
  @clock_skew_sec 5

  @doc """
  Verify a DPoP proof against the request it accompanied — the
  resource-server side of RFC 9449 (an ATProto resource host, or a space host
  serving credential-authed requests). Checks everything but replay: the
  caller records the returned `jti` itself.

  Verifies the proof's signature against its own embedded `jwk` header, its
  age (issued within the last 60s, ±5s clock skew), and that `htm`/`htu`
  match the request (`htu` compared after normalization, so query strings
  don't count).

  ## Options

  - `:credential` - the access token / space credential being presented; its
    hash must be bound into the proof as `ath`, and `ath` must be *absent*
    when no credential is given (e.g. the token-endpoint leg)
  - `:jkt` - an RFC 7638 thumbprint the presenting key must match (a space
    credential's `cnf.jkt` binding)
  - `:now` - pin the clock for tests

  Returns `{:ok, %{jti: ..., jkt: ...}}`, where `jkt` is the proof key's own
  thumbprint — equal to the bound key's whenever verification succeeds.
  """
  @spec verify_proof(binary(), String.t(), String.t(), keyword()) ::
          {:ok, %{jti: String.t(), jkt: String.t()}} | {:error, term()}
  def verify_proof(proof, htm, htu, opts \\ []) when is_binary(proof) do
    now = Keyword.get(opts, :now) || System.system_time(:second)

    with {:ok, header, claims} <- JWS.decode(proof),
         :ok <- check_proof_header(header),
         {:ok, _claims} <- JWS.verify(header["jwk"], proof, [@proof_alg]),
         :ok <- check_proof_age(claims, now),
         {:ok, jti} <- check_proof_request(claims, htm, htu),
         :ok <- check_proof_ath(claims, Keyword.get(opts, :credential)),
         {:ok, jkt} <- JWK.thumbprint(header["jwk"]),
         :ok <- check_bound_jkt(jkt, Keyword.get(opts, :jkt)) do
      {:ok, %{jti: jti, jkt: jkt}}
    else
      {:error, _} = error -> error
    end
  end

  defp check_proof_header(%{"typ" => @proof_typ, "alg" => @proof_alg, "jwk" => jwk})
       when is_map(jwk),
       do: :ok

  defp check_proof_header(_), do: {:error, :invalid_proof_header}

  defp check_proof_age(%{"iat" => iat}, now) when is_integer(iat) do
    cond do
      iat > now + @clock_skew_sec -> {:error, :proof_issued_in_future}
      now - iat > @proof_max_age_sec + @clock_skew_sec -> {:error, :proof_expired}
      true -> :ok
    end
  end

  defp check_proof_age(_, _), do: {:error, :invalid_proof}

  defp check_proof_request(
         %{"jti" => jti, "htm" => htm, "htu" => htu},
         expected_htm,
         expected_htu
       )
       when is_binary(jti) and jti != "" do
    if htm == expected_htm and htu == normalize_htu(expected_htu) do
      {:ok, jti}
    else
      {:error, :proof_request_mismatch}
    end
  end

  defp check_proof_request(_, _, _), do: {:error, :invalid_proof}

  defp check_proof_ath(%{"ath" => ath}, nil) when is_binary(ath), do: {:error, :unexpected_ath}

  defp check_proof_ath(claims, credential) when is_binary(credential) do
    if claims["ath"] == ath(credential), do: :ok, else: {:error, :ath_mismatch}
  end

  defp check_proof_ath(_, nil), do: :ok

  defp check_bound_jkt(jkt, expected) when is_binary(expected) do
    if jkt == expected, do: :ok, else: {:error, :key_mismatch}
  end

  defp check_bound_jkt(_, nil), do: :ok

  @doc """
  The origin (`scheme://host[:port]`, default ports dropped) of a URL.

  Used as the key for per-authorization-server nonce tracking.
  """
  @spec origin(String.t()) :: String.t()
  def origin(url) when is_binary(url) do
    url |> URI.parse() |> base()
  end

  @doc """
  Extract the `DPoP-Nonce` header from a response header list.
  """
  @spec nonce_header([{String.t(), String.t()}]) :: String.t() | nil
  def nonce_header(headers) when is_list(headers) do
    Enum.find_value(headers, fn
      {"dpop-nonce", value} -> value
      {key, value} when is_binary(key) -> if String.downcase(key) == "dpop-nonce", do: value
      _ -> nil
    end)
  end

  @doc """
  Whether an error response is a DPoP nonce challenge that should be retried
  (`400` with error `use_dpop_nonce`, or `401` carrying a `DPoP-Nonce`
  header) — and if so, the nonce to use.
  """
  @spec nonce_challenge?(%{
          status: pos_integer(),
          headers: [{String.t(), String.t()}],
          body: term()
        }) :: String.t() | nil
  def nonce_challenge?(%{status: 401, headers: headers}), do: nonce_header(headers)

  def nonce_challenge?(%{status: 400, headers: headers, body: %{"error" => "use_dpop_nonce"}}),
    do: nonce_header(headers)

  def nonce_challenge?(_), do: nil

  defp base(%URI{scheme: scheme0, host: host0, port: port}) do
    scheme = scheme0 && String.downcase(scheme0)
    host = host0 && String.downcase(host0)

    if is_nil(port) or port == URI.default_port(scheme) do
      "#{scheme}://#{host}"
    else
      "#{scheme}://#{host}:#{port}"
    end
  end

  defp path(%URI{path: path}) when path in [nil, ""], do: "/"
  defp path(%URI{path: path}), do: path

  defp jti do
    16
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  defp ath(nil), do: nil
  defp ath(token), do: :crypto.hash(:sha256, token) |> Base.url_encode64(padding: false)

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp alg(%{"crv" => "P-256"}), do: "ES256"
  defp alg(%{"crv" => "secp256k1"}), do: "ES256K"
  defp alg(_), do: nil
end
