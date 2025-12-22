defmodule Exosphere.ATProto.Identity.DID do
  @moduledoc """
  DID (Decentralized Identifier) resolution for Exosphere.ATProto.

  Exosphere.ATProto supports two DID methods:

  - `did:plc` - Bluesky's novel DID method with key rotation and recovery
  - `did:web` - W3C standard based on HTTPS/DNS

  ## Examples

      # Resolve a did:plc
      {:ok, doc} = Exosphere.ATProto.Identity.DID.resolve("did:plc:z72i7hdynmk6r22z27h6tvur")

      # Resolve a did:web
      {:ok, doc} = Exosphere.ATProto.Identity.DID.resolve("did:web:example.com")

      # Extract PDS endpoint from DID document
      {:ok, pds_url} = Exosphere.ATProto.Identity.DID.get_pds_endpoint(doc)

      # Extract signing key
      {:ok, public_key, curve} = Exosphere.ATProto.Identity.DID.get_signing_key(doc)
  """

  alias Exosphere.ATProto.Identity.DID.{PLC, Web}
  alias Exosphere.ATProto.Identity.Document

  @type did :: String.t()
  @type resolve_opts :: [timeout: pos_integer(), http_client: module()]

  @doc """
  Resolve a DID to its DID Document.

  Supports `did:plc` and `did:web` methods.

  ## Options

  - `:timeout` - HTTP request timeout in milliseconds (default: 10_000)

  ## Examples

      iex> Exosphere.ATProto.Identity.DID.resolve("did:plc:z72i7hdynmk6r22z27h6tvur")
      {:ok, %Document{...}}

      iex> Exosphere.ATProto.Identity.DID.resolve("did:web:example.com")
      {:ok, %Document{...}}

      iex> Exosphere.ATProto.Identity.DID.resolve("did:unsupported:xyz")
      {:error, :unsupported_did_method}
  """
  @spec resolve(did(), resolve_opts()) :: {:ok, Document.t()} | {:error, term()}
  def resolve(did, opts \\ [])

  def resolve("did:plc:" <> _ = did, opts) do
    PLC.resolve(did, opts)
  end

  def resolve("did:web:" <> _ = did, opts) do
    Web.resolve(did, opts)
  end

  def resolve("did:" <> _, _opts) do
    {:error, :unsupported_did_method}
  end

  def resolve(_, _opts) do
    {:error, :invalid_did_format}
  end

  @doc """
  Validate DID syntax according to Exosphere.ATProto rules.

  ## Examples

      iex> Exosphere.ATProto.Identity.DID.valid?("did:plc:z72i7hdynmk6r22z27h6tvur")
      true

      iex> Exosphere.ATProto.Identity.DID.valid?("not-a-did")
      false
  """
  @spec valid?(String.t()) :: boolean()
  def valid?(did) when is_binary(did) do
    Regex.match?(~r/^did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$/, did) and
      String.length(did) <= 2048
  end

  def valid?(_), do: false

  @doc """
  Parse the DID method from a DID string.

  ## Examples

      iex> Exosphere.ATProto.Identity.DID.method("did:plc:abc123")
      {:ok, :plc}

      iex> Exosphere.ATProto.Identity.DID.method("did:web:example.com")
      {:ok, :web}
  """
  @spec method(did()) :: {:ok, atom()} | {:error, :invalid_did}
  def method("did:plc:" <> _), do: {:ok, :plc}
  def method("did:web:" <> _), do: {:ok, :web}
  def method("did:" <> rest) when byte_size(rest) > 0, do: {:ok, :unknown}
  def method(_), do: {:error, :invalid_did}

  @doc """
  Extract the PDS (Personal Data Server) endpoint from a DID Document.

  Looks for a service with id `#atproto_pds` and type `AtprotoPersonalDataServer`.

  ## Examples

      iex> Exosphere.ATProto.Identity.DID.get_pds_endpoint(doc)
      {:ok, "https://pds.example.com"}
  """
  @spec get_pds_endpoint(Document.t()) :: {:ok, String.t()} | {:error, :not_found}
  def get_pds_endpoint(%Document{} = doc) do
    Document.get_pds_endpoint(doc)
  end

  @doc """
  Extract the Exosphere.ATProto signing key from a DID Document.

  Looks for a verification method with id `#atproto` and extracts the public key.

  ## Examples

      iex> Exosphere.ATProto.Identity.DID.get_signing_key(doc)
      {:ok, <<public_key_bytes>>, :secp256k1}
  """
  @spec get_signing_key(Document.t()) :: {:ok, binary(), atom()} | {:error, :not_found}
  def get_signing_key(%Document{} = doc) do
    Document.get_signing_key(doc)
  end

  @doc """
  Extract the handle (alsoKnownAs) from a DID Document.

  Returns the first `at://` URI from the alsoKnownAs array.

  ## Examples

      iex> Exosphere.ATProto.Identity.DID.get_handle(doc)
      {:ok, "alice.example.com"}
  """
  @spec get_handle(Document.t()) :: {:ok, String.t()} | {:error, :not_found}
  def get_handle(%Document{} = doc) do
    Document.get_handle(doc)
  end
end
