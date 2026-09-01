defmodule Exosphere.ATProto.Identity.Document do
  @moduledoc """
  DID Document structure and parsing for Exosphere.ATProto.

  A DID Document contains:
  - The DID itself
  - Verification methods (signing keys)
  - Service endpoints (PDS location)
  - Also known as (handles)
  """

  alias Exosphere.ATProto.AtUri
  alias Exosphere.ATProto.Base58

  @enforce_keys [:id]
  defstruct [
    :id,
    :also_known_as,
    :verification_method,
    :service
  ]

  @type verification_method :: %{
          id: String.t(),
          type: String.t(),
          controller: String.t(),
          public_key_multibase: String.t()
        }

  @type service :: %{
          id: String.t(),
          type: String.t(),
          service_endpoint: String.t()
        }

  @type t :: %__MODULE__{
          id: String.t(),
          also_known_as: [String.t()] | nil,
          verification_method: [verification_method()] | nil,
          service: [service()] | nil
        }

  @doc """
  Parse a raw DID Document map into a structured Document.

  ## Examples

      iex> Exosphere.ATProto.Identity.Document.parse(%{"id" => "did:plc:abc", ...})
      {:ok, %Document{...}}
  """
  @spec parse(map()) :: {:ok, t()} | {:error, term()}
  def parse(%{"id" => id} = raw) when is_binary(id) do
    doc = %__MODULE__{
      id: id,
      also_known_as: Map.get(raw, "alsoKnownAs"),
      verification_method: parse_verification_methods(Map.get(raw, "verificationMethod", [])),
      service: parse_services(Map.get(raw, "service", []))
    }

    {:ok, doc}
  end

  def parse(_), do: {:error, :invalid_document}

  defp parse_verification_methods(methods) when is_list(methods) do
    Enum.map(methods, fn method ->
      %{
        id: Map.get(method, "id"),
        type: Map.get(method, "type"),
        controller: Map.get(method, "controller"),
        public_key_multibase: Map.get(method, "publicKeyMultibase")
      }
    end)
  end

  defp parse_verification_methods(_), do: []

  defp parse_services(services) when is_list(services) do
    Enum.map(services, fn service ->
      %{
        id: Map.get(service, "id"),
        type: Map.get(service, "type"),
        service_endpoint: Map.get(service, "serviceEndpoint")
      }
    end)
  end

  defp parse_services(_), do: []

  @doc """
  Get the PDS endpoint from a DID Document.

  Looks for a service with id ending in `#atproto_pds` and type `AtprotoPersonalDataServer`.
  """
  @spec get_pds_endpoint(t()) :: {:ok, String.t()} | {:error, :not_found}
  def get_pds_endpoint(%__MODULE__{service: services}) when is_list(services) do
    case Enum.find(services, &pds_service?/1) do
      %{service_endpoint: endpoint} when is_binary(endpoint) -> {:ok, endpoint}
      _ -> {:error, :not_found}
    end
  end

  def get_pds_endpoint(_), do: {:error, :not_found}

  defp pds_service?(%{id: id, type: type}) do
    (String.ends_with?(id || "", "#atproto_pds") or id == "#atproto_pds") and
      type == "AtprotoPersonalDataServer"
  end

  defp pds_service?(_), do: false

  @doc """
  Get the space host endpoint from a DID Document.

  Spaces (proposal 0016) resolve a space authority through the
  `#atproto_space_host` service entry. The entry is optional: when absent, the
  space host falls back to the `#atproto_pds` service endpoint, per the
  proposal. Unlike the PDS service, the proposal does not constrain the entry's
  `type`, so the id fragment alone decides the match.

  ## Examples

      iex> {:ok, endpoint} = Document.get_space_host_endpoint(doc)
  """
  @spec get_space_host_endpoint(t()) :: {:ok, String.t()} | {:error, :not_found}
  def get_space_host_endpoint(%__MODULE__{} = doc) do
    case Enum.find(doc.service || [], &space_host_service?/1) do
      %{service_endpoint: endpoint} when is_binary(endpoint) ->
        {:ok, endpoint}

      _ ->
        get_pds_endpoint(doc)
    end
  end

  defp space_host_service?(%{id: id}) do
    String.ends_with?(id || "", "#atproto_space_host") or id == "#atproto_space_host"
  end

  defp space_host_service?(_), do: false

  @doc """
  Get the signing key from a DID Document.

  Looks for a verification method with id ending in `#atproto`.
  Returns the public key bytes and curve type.
  """
  @spec get_signing_key(t()) :: {:ok, binary(), atom()} | {:error, :not_found}
  def get_signing_key(%__MODULE__{verification_method: methods}) when is_list(methods) do
    case Enum.find(methods, &atproto_key?/1) do
      %{public_key_multibase: multibase, type: type} when is_binary(multibase) ->
        parse_multibase_key(multibase, type)

      _ ->
        {:error, :not_found}
    end
  end

  def get_signing_key(_), do: {:error, :not_found}

  defp atproto_key?(%{id: id}) do
    String.ends_with?(id || "", "#atproto") or id == "#atproto"
  end

  defp atproto_key?(_), do: false

  @doc """
  Get the space signing key from a DID Document.

  Spaces (proposal 0016) verify space credentials against the verification
  method with id `#atproto_space`. The entry is optional: when absent, the key
  falls back to the account's `#atproto` signing key, per the proposal.

  Note that the fallback keys off the exact `#atproto` fragment — a published
  `#atproto_space` entry is never picked up by `get_signing_key/1`.

  This guesses, which is only safe for an authority that publishes one of the
  two. Prefer `get_space_signing_key/2` wherever a token's `kid` says which
  key signed it.
  """
  @spec get_space_signing_key(t()) :: {:ok, binary(), atom()} | {:error, term()}
  def get_space_signing_key(%__MODULE__{verification_method: methods} = doc)
      when is_list(methods) do
    case Enum.find(methods, &space_key?/1) do
      %{public_key_multibase: multibase, type: type} when is_binary(multibase) ->
        parse_multibase_key(multibase, type)

      _ ->
        get_signing_key(doc)
    end
  end

  def get_space_signing_key(_), do: {:error, :not_found}

  @doc """
  Resolve the verification method a space token's `kid` names.

  A space token's header names the fragment its signing key was published
  under, so a verifier honours it rather than guessing: an authority that
  publishes both keys signs some tokens with each, and picking the wrong one
  fails a perfectly good signature.

  Only `#atproto` and `#atproto_space` are addressable — a token may not point
  the verifier at an unrelated verification method (a rotation key, say).
  Anything else is `{:error, :unsupported_space_kid}`; a fragment that is
  addressable but absent from the document is `{:error, :not_found}`. Both
  bare (`"#atproto_space"`) and absolute (`"did:plc:abc#atproto_space"`) key
  ids are accepted.

  A `nil` `kid` has nothing to honour and falls back to
  `get_space_signing_key/1`.
  """
  @spec get_space_signing_key(t(), String.t() | nil) ::
          {:ok, binary(), atom()} | {:error, term()}
  def get_space_signing_key(doc, nil), do: get_space_signing_key(doc)

  def get_space_signing_key(%__MODULE__{verification_method: methods}, kid)
      when is_binary(kid) and is_list(methods) do
    with {:ok, fragment} <- space_key_fragment(kid) do
      case Enum.find(methods, &fragment?(&1, fragment)) do
        %{public_key_multibase: multibase, type: type} when is_binary(multibase) ->
          parse_multibase_key(multibase, type)

        _ ->
          {:error, :not_found}
      end
    end
  end

  def get_space_signing_key(_, kid) when is_binary(kid) do
    with {:ok, _fragment} <- space_key_fragment(kid), do: {:error, :not_found}
  end

  @space_key_fragments ["atproto", "atproto_space"]

  defp space_key_fragment(kid) do
    case kid |> String.split("#") |> List.last() do
      fragment when fragment in @space_key_fragments -> {:ok, fragment}
      _ -> {:error, :unsupported_space_kid}
    end
  end

  defp fragment?(%{id: id}, fragment) when is_binary(id),
    do: String.ends_with?(id, "#" <> fragment)

  defp fragment?(_, _), do: false

  defp space_key?(%{id: id}) do
    String.ends_with?(id || "", "#atproto_space") or id == "#atproto_space"
  end

  defp space_key?(_), do: false

  defp parse_multibase_key("z" <> encoded, type) do
    # Base58btc encoded
    case Base58.decode(encoded) do
      {:ok, bytes} -> parse_multicodec_key(bytes, type)
      :error -> {:error, :invalid_multibase}
    end
  end

  defp parse_multibase_key(_, _), do: {:error, :unsupported_multibase}

  defp parse_multicodec_key(<<0xE7, 0x01, key::binary-33>>, _type) do
    # secp256k1 compressed (multicodec varint 0xe7 0x01)
    {:ok, key, :secp256k1}
  end

  defp parse_multicodec_key(<<0x80, 0x24, key::binary-33>>, _type) do
    # P-256 compressed
    {:ok, key, :p256}
  end

  # Legacy format without multicodec prefix
  defp parse_multicodec_key(key, "EcdsaSecp256k1VerificationKey2019") when byte_size(key) == 65 do
    # Uncompressed secp256k1, need to compress
    {:ok, compress_key(key), :secp256k1}
  end

  defp parse_multicodec_key(key, "EcdsaSecp256r1VerificationKey2019") when byte_size(key) == 65 do
    # Uncompressed P-256, need to compress
    {:ok, compress_key(key), :p256}
  end

  defp parse_multicodec_key(key, "Multikey") when byte_size(key) >= 33 do
    # Try to detect from key prefix (multicodec varints)
    case key do
      <<0xE7, 0x01, rest::binary-33>> -> {:ok, rest, :secp256k1}
      <<0x80, 0x24, rest::binary-33>> -> {:ok, rest, :p256}
      _ -> {:error, :unknown_key_type}
    end
  end

  defp parse_multicodec_key(_, _), do: {:error, :unknown_key_type}

  defp compress_key(<<0x04, x::binary-32, y::binary-32>>) do
    prefix = if rem(:binary.decode_unsigned(y), 2) == 0, do: 0x02, else: 0x03
    <<prefix, x::binary>>
  end

  defp compress_key(key), do: key

  @doc """
  Get the handle from a DID Document.

  Returns the first `at://` URI from alsoKnownAs, extracting just the handle.
  """
  @spec get_handle(t()) :: {:ok, String.t()} | {:error, :not_found}
  def get_handle(%__MODULE__{also_known_as: aliases}) when is_list(aliases) do
    aliases
    |> Enum.filter(&is_binary/1)
    |> Enum.find_value({:error, :not_found}, fn aka ->
      case AtUri.parse(aka) do
        {:ok, %{authority: authority}} -> {:ok, authority}
        {:error, _} -> nil
      end
    end)
  end

  def get_handle(_), do: {:error, :not_found}
end
