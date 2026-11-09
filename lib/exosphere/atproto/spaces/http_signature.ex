defmodule Exosphere.ATProto.Spaces.HttpSignature do
  @moduledoc """
  Space credential key binding (proposal 0016, "Credential key binding" and
  "Presenting a space credential"; atproto `b34848587`, `94de8ab02`,
  `57b24c6`, `75e017c`): every request authorized by a space credential
  carries an RFC 9421 HTTP Message Signature, made by the key the credential
  is bound to (its `cnf.kid`), over the credential and its audience DID.

      Authorization: Atproto-Space-Credential <space-credential>
      Atproto-Space-Audience: did:plc:repoOwner
      Signature-Input: atproto-space-credential=("authorization" "atproto-space-audience");tag="atproto-space-credential"
      Signature: atproto-space-credential=:wNmSUA...:

  The audience is the repo owner's DID when syncing a repo, and the space
  authority's DID for requests to the space host. The signature binds
  neither method nor URI, so one signature may be reused with the same
  credential and audience until the credential expires.

  The key is a fresh P-256 keypair per credential (`generate_key/0`); its
  `did:key` is what `Spaces.Credential.mint/4` sends as `credentialKey`.
  Signatures are `ecdsa-p256-sha256`, the 64-byte `r || s` encoding;
  verifiers accept both low-S and high-S signatures, as the proposal
  requires. This module replaces the DPoP binding (`cnf.jkt`) the alpha used
  until those commits.
  """

  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.Spaces.StructuredFields, as: SF

  @label "atproto-space-credential"
  @tag "atproto-space-credential"
  @alg "ecdsa-p256-sha256"
  @components ["authorization", "atproto-space-audience"]

  @typedoc """
  A credential key: a P-256 keypair (`Crypto.generate_keypair(:p256)` shape)
  plus its `did:key`.
  """
  @type key :: %{private_key: binary(), public_key: binary(), did_key: String.t()}

  @type headers :: [{String.t(), String.t()}] | %{optional(String.t()) => String.t()}

  @doc "Generate a fresh credential key (P-256)."
  @spec generate_key() :: {:ok, key()}
  def generate_key do
    {:ok, keypair} = Crypto.generate_keypair(:p256)
    {:ok, did_key} = Crypto.to_did_key(keypair.public_key, :p256)
    {:ok, Map.put(keypair, :did_key, did_key)}
  end

  @doc "Rebuild a credential key from a 32-byte P-256 private key."
  @spec key_from_private(binary()) :: {:ok, key()} | {:error, :invalid_private_key}
  def key_from_private(<<_::binary-32>> = private_key) do
    {public, _} = :crypto.generate_key(:ecdh, :secp256r1, private_key)
    {:ok, compressed} = Crypto.compress_public_key(public, :p256)
    {:ok, did_key} = Crypto.to_did_key(compressed, :p256)
    {:ok, %{private_key: private_key, public_key: compressed, did_key: did_key}}
  rescue
    _ -> {:error, :invalid_private_key}
  end

  def key_from_private(_), do: {:error, :invalid_private_key}

  @doc """
  The four request headers that present `credential` to `audience`:
  `authorization`, `atproto-space-audience`, `signature-input`, `signature`.
  """
  @spec headers(key(), String.t(), String.t()) :: {:ok, [{String.t(), String.t()}]}
  def headers(%{private_key: _} = key, credential, audience)
      when is_binary(credential) and is_binary(audience) do
    authorization = "Atproto-Space-Credential " <> credential
    {signature_input, signature} = sign(key, authorization, audience)

    {:ok,
     [
       {"authorization", authorization},
       {"atproto-space-audience", audience},
       {"signature-input", SF.serialize_dictionary([{@label, signature_input}])},
       {"signature", SF.serialize_dictionary([{@label, {{:bytes, signature}, []}}])}
     ]}
  end

  @doc """
  Sign an `Authorization` value and audience DID. Returns the parsed
  signature-input member and the 64-byte signature.
  """
  @spec sign(key(), String.t(), String.t()) :: {SF.inner_list(), binary()}
  def sign(%{private_key: private_key}, authorization, audience) do
    input = {:inner_list, Enum.map(@components, &{&1, []}), [{"tag", @tag}]}
    base = signature_base([authorization, audience], SF.serialize_member(input))
    {:ok, signature} = Crypto.sign(base, private_key, :p256)
    {input, signature}
  end

  @doc """
  The RFC 9421 signature base over the two covered fields, in order:

      "authorization": <value>
      "atproto-space-audience": <value>
      "@signature-params": <serialized signature-input member>

  Field values are trimmed of surrounding whitespace and otherwise taken
  exactly as sent — no case normalisation of the `Authorization` scheme.
  """
  @spec signature_base([String.t()], String.t()) :: binary()
  def signature_base([authorization, audience], signature_params) do
    Enum.join(
      [
        ~s("authorization": ) <> String.trim(authorization),
        ~s("atproto-space-audience": ) <> String.trim(audience),
        ~s("@signature-params": ) <> signature_params
      ],
      "\n"
    )
  end

  @doc """
  Verify a request's `atproto-space-credential` signature against `key_id`
  (the credential's `cnf.kid`, a P-256 `did:key`), checking what the proposal
  requires a receiving host to check:

  - `authorization` and `atproto-space-audience` are present and non-empty
  - the signature covers exactly `("authorization" "atproto-space-audience")`
  - its `tag` is `atproto-space-credential`; an `alg`, if present, is
    `ecdsa-p256-sha256`; a `keyid`, if present, equals `key_id`
  - `key_id` is a P-256 `did:key`, and the 64-byte signature verifies
    against it (high-S accepted)

  `headers` is a list of `{name, value}` (names matched case-insensitively)
  or a map with lowercase names. It does not check the credential itself or
  that the audience is the right one for the request — see
  `Spaces.Credential.verify_request/2`, which does all of it.
  """
  @spec verify(headers(), String.t()) :: :ok | {:error, term()}
  def verify(headers, key_id) do
    headers = normalize(headers)

    with {:ok, authorization} <- required(headers, "authorization"),
         {:ok, audience} <- required(headers, "atproto-space-audience"),
         {:ok, input, signature} <- parse(headers),
         :ok <- check_covered(input),
         :ok <- check_params(input, key_id),
         {:ok, public_key} <- p256_did_key(key_id) do
      base = signature_base([authorization, audience], SF.serialize_member(input))

      case Crypto.verify(base, signature, public_key, :p256, allow_high_s: true) do
        :ok -> :ok
        {:error, _} -> {:error, :invalid_http_signature}
      end
    end
  end

  @doc "Whether `key_id` is a P-256 `did:key` — the only key a credential can bind."
  @spec p256_did_key?(String.t()) :: boolean()
  def p256_did_key?(key_id), do: match?({:ok, _}, p256_did_key(key_id))

  defp p256_did_key(key_id) when is_binary(key_id) do
    case Crypto.from_did_key(key_id) do
      {:ok, public_key, :p256} -> {:ok, public_key}
      _ -> {:error, :invalid_signature_key}
    end
  end

  defp p256_did_key(_), do: {:error, :invalid_signature_key}

  defp parse(headers) do
    with {:ok, input_header} <- required(headers, "signature-input"),
         {:ok, signature_header} <- required(headers, "signature"),
         {:ok, inputs} <- SF.parse_dictionary(input_header),
         {:ok, signatures} <- SF.parse_dictionary(signature_header),
         {_, {:inner_list, _, _} = input} <- List.keyfind(inputs, @label, 0),
         {_, {{:bytes, signature}, []}} when byte_size(signature) == 64 <-
           List.keyfind(signatures, @label, 0) do
      {:ok, input, signature}
    else
      {:error, {:missing_header, _}} = error -> error
      _ -> {:error, :malformed_http_signature}
    end
  end

  defp check_covered({:inner_list, items, _params}) do
    if Enum.map(items, fn {bare, params} -> {bare, params} end) ==
         Enum.map(@components, &{&1, []}),
       do: :ok,
       else: {:error, :wrong_covered_components}
  end

  defp check_params({:inner_list, _items, params}, key_id) do
    cond do
      List.keyfind(params, "tag", 0) != {"tag", @tag} ->
        {:error, :wrong_signature_tag}

      match?({_, alg} when alg != @alg, List.keyfind(params, "alg", 0)) ->
        {:error, :wrong_signature_alg}

      match?({_, keyid} when keyid != key_id, List.keyfind(params, "keyid", 0)) ->
        {:error, :signature_keyid_mismatch}

      true ->
        :ok
    end
  end

  defp required(headers, name) do
    case Map.get(headers, name) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, {:missing_header, name}}
    end
  end

  defp normalize(headers) when is_map(headers),
    do: Map.new(headers, fn {k, v} -> {String.downcase(k), v} end)

  defp normalize(headers) when is_list(headers) do
    Enum.reduce(headers, %{}, fn {k, v}, acc -> Map.put_new(acc, String.downcase(k), v) end)
  end
end
