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

  A space authority's space host is its PDS, like any other atproto account:
  this is the `#atproto_pds` service endpoint (`get_pds_endpoint/1`).

  Until atproto `432ef66` (2026-10-20) an authority could publish a dedicated
  `#atproto_space_host` service entry that took precedence. Upstream dropped
  it — delegation tokens and client attestations are now addressed to
  `{authority}#atproto_pds` (`Spaces.Token.space_host_aud/1`) — so an
  `#atproto_space_host` entry is ignored here rather than routed to: a host
  reached through it would refuse tokens addressed to the PDS fragment.

  ## Examples

      iex> {:ok, endpoint} = Document.get_space_host_endpoint(doc)
  """
  @spec get_space_host_endpoint(t()) :: {:ok, String.t()} | {:error, :not_found}
  def get_space_host_endpoint(%__MODULE__{} = doc), do: get_pds_endpoint(doc)
  def get_space_host_endpoint(_), do: {:error, :not_found}

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
  Get the space signing key from a DID Document: the key space credentials
  are verified against.

  This is the account's `#atproto` signing key (`get_signing_key/1`). Until
  atproto `432ef66` (2026-10-20) an authority could publish a dedicated
  `#atproto_space` verification method that took precedence; upstream dropped
  it, and credentials must now name `kid: "#atproto"` exactly, so an
  `#atproto_space` entry is never consulted.
  """
  @spec get_space_signing_key(t()) :: {:ok, binary(), atom()} | {:error, term()}
  def get_space_signing_key(%__MODULE__{} = doc), do: get_signing_key(doc)
  def get_space_signing_key(_), do: {:error, :not_found}

  @doc """
  Resolve the verification method a space token's `kid` names.

  Delegation tokens and space credentials carry `kid: "#atproto"` — exactly
  that string, the bare fragment (atproto `432ef66`/`75e017c`, matching the
  reference PDS's check). Anything else, an absolute
  `"did:plc:abc#atproto"` included, is `{:error, :unsupported_space_kid}`; a
  missing `kid` is `{:error, :missing_kid}`. The resolved key is the
  document's `#atproto` key, `{:error, :not_found}` when it has none.
  """
  @spec get_space_signing_key(t(), String.t() | nil) ::
          {:ok, binary(), atom()} | {:error, term()}
  def get_space_signing_key(_doc, nil), do: {:error, :missing_kid}
  def get_space_signing_key(doc, "#atproto"), do: get_space_signing_key(doc)
  def get_space_signing_key(_doc, kid) when is_binary(kid), do: {:error, :unsupported_space_kid}

  @doc """
  Get the KEM public key from a DID Document: the `#atproto_kem` verification
  method (proposal 0016, "KEM key"; atproto `5791385`).

  Every account with space repos publishes a P-256 key under this id; a
  syncer derives a per-request shared secret against it
  (`Spaces.Kem.encapsulate/1`) so the repo host can MAC what it serves. Only
  a P-256 key qualifies — any other curve is `{:error, :invalid_kem_key}`.

  Returns the compressed public key.
  """
  @spec get_kem_key(t()) :: {:ok, binary()} | {:error, term()}
  def get_kem_key(%__MODULE__{verification_method: methods}) when is_list(methods) do
    case Enum.find(methods, &fragment?(&1, "atproto_kem")) do
      %{public_key_multibase: multibase, type: type} when is_binary(multibase) ->
        case parse_multibase_key(multibase, type) do
          {:ok, key, :p256} -> {:ok, key}
          {:ok, _key, _other} -> {:error, :invalid_kem_key}
          {:error, _} = error -> error
        end

      _ ->
        {:error, :not_found}
    end
  end

  def get_kem_key(_), do: {:error, :not_found}

  defp fragment?(%{id: id}, fragment) when is_binary(id),
    do: String.ends_with?(id, "#" <> fragment)

  defp fragment?(_, _), do: false

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
