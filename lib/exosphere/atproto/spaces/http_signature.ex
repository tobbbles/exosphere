defmodule Exosphere.ATProto.Spaces.HttpSignature do
  @moduledoc """
  RFC 9421 HTTP Message Signatures as atproto Spaces uses them: the signature
  that presents a space credential, and the shared helpers `Spaces.Mac` builds
  its MACs on (proposal 0016, "Credential key binding", "Presenting a space
  credential"; atproto `#5862`, in the November 12 alpha).

  ## Credential signatures

  Every request authorized by a space credential carries a signature made by
  the key the credential is bound to (its `cnf.kid`), over the credential and
  its audience DID:

      Authorization: Atproto-Space-Credential <space-credential>
      Atproto-Space-Audience: did:plc:repoOwner
      Signature-Input: sig=("authorization" "atproto-space-audience");tag="atproto-space-credential"
      Signature: sig=:wNmSUA...:

  The audience is the repo owner's DID when syncing a repo, and the space
  authority's DID for requests to the space host. The signature binds neither
  method nor URI, so one signature may be reused with the same credential and
  audience until the credential expires.

  Labels carry no meaning (RFC 9421 §7.2.5): a verifier finds the signature
  by its `tag`, under whatever label the signer chose. This module signs
  under `sig`, as the reference does; until the November 12 alpha both sides
  used the label `atproto-space-credential`, and verifiers looked it up by
  that label.

  The key is a fresh P-256 keypair per credential (`generate_key/0`); its
  `did:key` is what `Spaces.Credential.authorize_space_sync/4` sends as `credentialKey`.
  Signatures are `ecdsa-p256-sha256`, the 64-byte `r || s` encoding;
  verifiers accept both low-S and high-S signatures, as the proposal
  requires.

  ## Shared RFC 9421 helpers

  `find_signature/3`, `members_with_tag/2`, `format_components/1` and
  `signature_base/3` mirror the helpers of the same names in the reference's
  `http-signature.ts`. `Spaces.Mac` uses them for its `hmac-sha256` MACs.
  """

  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.Spaces.StructuredFields, as: SF

  @label "sig"
  @tag "atproto-space-credential"
  @alg "ecdsa-p256-sha256"
  @components [{"authorization", []}, {"atproto-space-audience", []}]

  # Fields that are RFC 9651 Dictionaries: repeated field lines combine into
  # one list (RFC 9110 §5.3), rather than the first one winning.
  @dictionary_fields ~w(signature-input signature accept-signature atproto-space-commit atproto-space-record)

  @typedoc """
  A credential key: a P-256 keypair (`Crypto.generate_keypair(:p256)` shape)
  plus its `did:key`.
  """
  @type key :: %{private_key: binary(), public_key: binary(), did_key: String.t()}

  @typedoc """
  Message headers: `{name, value}` pairs (names matched case-insensitively),
  or a map of names to a value or a list of values (as `Req` returns them).
  """
  @type headers ::
          [{String.t(), String.t()}]
          | %{optional(String.t()) => String.t() | [String.t()]}

  @typedoc """
  What an application requires of the signature it verifies (RFC 9421
  §3.2.1): the `tag` that identifies it, exactly the `components` it must
  cover (in order), and the `alg` and `key_id` its `alg` and `keyid`
  parameters must name if present.
  """
  @type requirements :: %{
          tag: String.t(),
          components: [SF.item()],
          alg: String.t(),
          key_id: String.t()
        }

  @typedoc "A signature found by `find_signature/3`."
  @type found :: %{label: String.t(), signature_params: String.t(), signature: binary()}

  @typedoc """
  Why `find_signature/3` refused a message:

  - `:missing_http_signature` — no `Signature-Input`/`Signature` field, no
    member with the tag, or no well-formed signature under its label
  - `:malformed_http_signature` — a field that is not a valid Dictionary
  - `:multiple_http_signatures` — more than one member with the tag
  - `:wrong_covered_components`, `:wrong_signature_alg`,
    `:signature_keyid_mismatch` — the requirements are not met
  """
  @type find_error ::
          :missing_http_signature
          | :malformed_http_signature
          | :multiple_http_signatures
          | :wrong_covered_components
          | :wrong_signature_alg
          | :signature_keyid_mismatch

  # -- credential keys --------------------------------------------------------

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

  @doc "Whether `key_id` is a P-256 `did:key` — the only key a credential can bind."
  @spec p256_did_key?(String.t()) :: boolean()
  def p256_did_key?(key_id), do: match?({:ok, _}, p256_did_key(key_id))

  # -- credential signatures --------------------------------------------------

  @doc """
  The four request headers that present `credential` to `audience`:
  `authorization`, `atproto-space-audience`, `signature-input`, `signature`.
  The signature is under the label `sig`.
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
  Sign an `Authorization` value and audience DID. Returns the signature-input
  member (an inner list tagged `atproto-space-credential`) and the 64-byte
  signature.
  """
  @spec sign(key(), String.t(), String.t()) :: {SF.inner_list(), binary()}
  def sign(%{private_key: private_key}, authorization, audience) do
    input = {:inner_list, @components, [{"tag", @tag}]}
    base = signature_base(@components, [authorization, audience], SF.serialize_member(input))
    {:ok, signature} = Crypto.sign(base, private_key, :p256)
    {input, signature}
  end

  @doc """
  Verify a request's credential signature against `key_id` (the credential's
  `cnf.kid`, a P-256 `did:key`), checking what the proposal requires of a
  receiving host:

  - `authorization` and `atproto-space-audience` are present and non-empty
  - exactly one signature is tagged `atproto-space-credential`, under any
    label (`find_signature/3`)
  - it covers exactly `("authorization" "atproto-space-audience")`, in order
  - a `keyid`, if present, equals `key_id`; an `alg`, if present, is
    `ecdsa-p256-sha256`; other parameters (such as `created`) are covered by
    the signature but not interpreted
  - `key_id` is a P-256 `did:key`, and the 64-byte signature verifies
    against it (high-S accepted)

  It does not check the credential itself or that the audience is the right
  one for the request — see `Spaces.Credential.verify_request/2`, which does
  all of it.

  Errors: `{:missing_header, name}`, a `t:find_error/0`,
  `:invalid_signature_key`, or `:invalid_http_signature`.
  """
  @spec verify(headers(), String.t()) ::
          :ok
          | {:error,
             {:missing_header, String.t()}
             | find_error()
             | :invalid_signature_key
             | :invalid_http_signature}
  def verify(headers, key_id) do
    headers = normalize_headers(headers)
    requirements = %{tag: @tag, components: @components, alg: @alg, key_id: key_id}

    with {:ok, authorization} <- required(headers, "authorization"),
         {:ok, audience} <- required(headers, "atproto-space-audience"),
         {:ok, found} <-
           find_signature(headers["signature-input"], headers["signature"], requirements),
         {:ok, public_key} <- p256_did_key(key_id) do
      base = signature_base(@components, [authorization, audience], found.signature_params)

      case Crypto.verify(base, found.signature, public_key, :p256, allow_high_s: true) do
        :ok -> :ok
        {:error, _} -> {:error, :invalid_http_signature}
      end
    end
  end

  # -- RFC 9421 helpers, shared with Spaces.Mac -------------------------------

  @doc """
  Find the one signature tagged `requirements.tag` in a message's
  `Signature-Input` and `Signature` field values, and check it meets the
  requirements. Labels carry no meaning, so the tag is what identifies it;
  other parameters, like `created`, are covered by the signature but not
  interpreted. The `Signature` member must be a bare Byte Sequence.

  Returns the label, the signature's parameters re-serialized canonically (as
  the signature base needs them), and the signature bytes.
  """
  @spec find_signature(String.t() | nil, String.t() | nil, requirements()) ::
          {:ok, found()} | {:error, find_error()}
  def find_signature(input_field, signature_field, %{tag: tag} = required)
      when is_binary(input_field) and is_binary(signature_field) do
    with {:ok, inputs} <- parse_field(input_field),
         {:ok, signatures} <- parse_field(signature_field) do
      case members_with_tag(inputs, tag) do
        [] ->
          {:error, :missing_http_signature}

        [{label, {:inner_list, components, params} = input}] ->
          with {:ok, signature} <- get_signature(signatures, label),
               :ok <- check_requirements(components, params, required) do
            {:ok,
             %{label: label, signature_params: SF.serialize_member(input), signature: signature}}
          end

        [_, _ | _] ->
          {:error, :multiple_http_signatures}
      end
    end
  end

  def find_signature(_input_field, _signature_field, _required),
    do: {:error, :missing_http_signature}

  @doc """
  The members of a parsed `Signature-Input` or `Accept-Signature` Dictionary
  whose `tag` parameter is the String `tag` (a Token with the same characters
  does not match), in field order, as `{label, inner_list}`.
  """
  @spec members_with_tag(SF.dictionary(), String.t()) :: [{String.t(), SF.inner_list()}]
  def members_with_tag(members, tag) do
    for {label, {:inner_list, _items, params} = member} <- members,
        List.keyfind(params, "tag", 0) == {"tag", tag},
        do: {label, member}
  end

  @doc """
  A covered component list without its parameters, e.g.
  `("authorization" "atproto-space-audience")` or `("atproto-space-commit";sf)`.
  Component parameters (like `sf`) are part of it.
  """
  @spec format_components([SF.item()]) :: String.t()
  def format_components(components), do: SF.serialize_member({:inner_list, components, []})

  @doc """
  The signature base (RFC 9421 §2.5) for a signature covering `components`
  (header-field items, e.g. `{"authorization", []}` or
  `{"atproto-space-commit", [{"sf", true}]}`), whose values are given in the
  same order, under the serialized `signature_params`:

      "authorization": <value>
      "atproto-space-audience": <value>
      "@signature-params": <signature params>

  Values are trimmed of surrounding whitespace and otherwise taken exactly as
  given — a component flagged `sf` must be passed already canonicalized.
  """
  @spec signature_base([SF.item()], [String.t()], String.t()) :: binary()
  def signature_base(components, values, signature_params)
      when length(components) == length(values) do
    lines =
      Enum.zip_with(components, values, fn component, value ->
        SF.serialize_member(component) <> ": " <> String.trim(value)
      end)

    Enum.join(lines ++ [~s("@signature-params": ) <> signature_params], "\n")
  end

  @doc """
  Normalize message headers to a map of lowercase names to one string value.
  Repeated Dictionary fields (`signature-input`, `signature`,
  `accept-signature`, and the MAC-covered headers) combine with `", "`, as
  RFC 9110 §5.3 combines list-valued fields; for any other field the first
  value wins.
  """
  @spec normalize_headers(headers()) :: %{optional(String.t()) => String.t()}
  def normalize_headers(headers) when is_map(headers) or is_list(headers) do
    headers
    |> Enum.flat_map(fn
      {name, values} when is_list(values) -> Enum.map(values, &{String.downcase(name), &1})
      {name, value} -> [{String.downcase(name), value}]
    end)
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Map.new(fn
      {name, values} when name in @dictionary_fields -> {name, Enum.join(values, ", ")}
      {name, [value | _]} -> {name, value}
    end)
  end

  # -- private ----------------------------------------------------------------

  defp parse_field(value) do
    case SF.parse_dictionary(value) do
      {:ok, dict} -> {:ok, dict}
      {:error, _} -> {:error, :malformed_http_signature}
    end
  end

  defp get_signature(signatures, label) do
    case List.keyfind(signatures, label, 0) do
      {_, {{:bytes, signature}, []}} -> {:ok, signature}
      _ -> {:error, :missing_http_signature}
    end
  end

  defp check_requirements(components, params, required) do
    cond do
      format_components(components) != format_components(required.components) ->
        {:error, :wrong_covered_components}

      match?({_, alg} when alg != required.alg, List.keyfind(params, "alg", 0)) ->
        {:error, :wrong_signature_alg}

      match?({_, keyid} when keyid != required.key_id, List.keyfind(params, "keyid", 0)) ->
        {:error, :signature_keyid_mismatch}

      true ->
        :ok
    end
  end

  defp p256_did_key(key_id) when is_binary(key_id) do
    case Crypto.from_did_key(key_id) do
      {:ok, public_key, :p256} -> {:ok, public_key}
      _ -> {:error, :invalid_signature_key}
    end
  end

  defp p256_did_key(_), do: {:error, :invalid_signature_key}

  defp required(headers, name) do
    case Map.get(headers, name) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, {:missing_header, name}}
    end
  end
end
