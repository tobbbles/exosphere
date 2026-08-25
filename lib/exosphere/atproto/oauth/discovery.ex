defmodule Exosphere.ATProto.OAuth.Discovery do
  @moduledoc """
  Identity-to-authorization-server discovery for ATProto OAuth.

  The authorization server for an account is reached through its identity:

  1. Resolve the login hint (handle or DID) to a DID document —
     `Exosphere.ATProto.Identity`.
  2. Take the PDS service endpoint (`#atproto_pds`) from the document.
  3. Fetch the PDS's resource-server metadata
     (`/.well-known/oauth-protected-resource`) to find its authorization
     server.
  4. Fetch and validate the authorization server metadata
     (`/.well-known/oauth-authorization-server`).

  Starting from a bare server URL ("server flow") skips identity resolution;
  the account is instead verified after the token exchange via
  `verify_subject/3`.

  ## Examples

      {:ok, resolved} = Exosphere.ATProto.OAuth.Discovery.resolve("alice.example.com")
      resolved.auth_server.issuer
  """

  alias Exosphere.ATProto.HTTP
  alias Exosphere.ATProto.Identity.{DID, Document, Handle}
  alias Exosphere.ATProto.OAuth.{DPoP, ServerMetadata}

  defstruct [:did, :handle, :pds, :did_document, :auth_server]

  @type t :: %__MODULE__{
          did: String.t() | nil,
          handle: String.t() | nil,
          pds: String.t() | nil,
          did_document: Document.t() | nil,
          auth_server: ServerMetadata.t()
        }

  @type opts :: [timeout: pos_integer(), http: module()]

  @doc """
  Resolve an identity (handle, DID, or server URL) to its authorization
  server.

  Handles are resolved to DIDs and verified bidirectionally against the DID
  document's `alsoKnownAs`. Server URLs resolve directly to an authorization
  server (or, with a 404 resource-server document, the server itself acting
  as its own AS); identity fields stay `nil` until `verify_subject/3`.
  """
  @spec resolve(String.t(), opts()) :: {:ok, t()} | {:error, term()}
  def resolve(identifier, opts \\ [])

  def resolve("did:" <> _ = did, opts), do: resolve_did(did, nil, opts)

  def resolve("https://" <> _ = url, opts), do: resolve_server(url, opts)

  def resolve("http://" <> _ = url, opts), do: resolve_server(url, opts)

  def resolve(handle, opts) when is_binary(handle) and byte_size(handle) > 0 do
    # HTTPS well-known before DNS TXT: deterministic ordering (and injection
    # through :http stays meaningful); both methods are spec-valid.
    handle_opts =
      opts
      |> Keyword.take([:timeout, :http])
      |> Keyword.put(:http_client, http(opts))
      |> Keyword.put(:methods, [:https, :dns])

    # Only the resolution step is wrapped: failures past it (e.g. a
    # bidirectional handle mismatch) are already specific.
    case Handle.resolve(handle, handle_opts) do
      {:ok, did} -> resolve_did(did, handle, opts)
      {:error, reason} -> {:error, {:handle_resolution_failed, reason}}
    end
  end

  def resolve(_, _), do: {:error, :invalid_identifier}

  @doc """
  Resolve a DID (with optional expected handle for the bidirectional check)
  through to its authorization server.
  """
  @spec resolve_did(String.t(), String.t() | nil, opts()) :: {:ok, t()} | {:error, term()}
  def resolve_did(did, handle \\ nil, opts) do
    with {:ok, %Document{} = doc} <- DID.resolve(did, did_opts(opts)),
         :ok <- check_handle(doc, handle),
         {:ok, pds} <- pds_endpoint(doc),
         {:ok, auth_server} <- authorization_server(pds, opts) do
      {:ok,
       %__MODULE__{
         did: did,
         handle: handle,
         pds: pds,
         did_document: doc,
         auth_server: auth_server
       }}
    end
  end

  @doc """
  Find the authorization server for a PDS (or any resource server) origin:
  resource-server metadata, then authorization-server metadata.
  """
  @spec authorization_server(String.t(), opts()) :: {:ok, ServerMetadata.t()} | {:error, term()}
  def authorization_server(pds_url, opts) do
    origin = DPoP.origin(pds_url)

    with {:ok, as_origin} <- ServerMetadata.fetch_authorization_server(origin, opts) do
      ServerMetadata.fetch(as_origin, opts)
    end
  end

  @doc """
  Verify a `sub` DID from a server-flow token exchange against the expected
  authorization-server issuer: the DID's PDS must declare (via its
  resource-server metadata) an authorization server whose `issuer` matches.
  """
  @spec verify_subject(String.t(), String.t(), opts()) :: {:ok, t()} | {:error, term()}
  def verify_subject(did, expected_issuer, opts) do
    with {:ok, %__MODULE__{} = resolved} <- resolve_did(did, nil, opts),
         :ok <- check_issuer(resolved.auth_server, expected_issuer) do
      {:ok, resolved}
    end
  end

  defp resolve_server(url, opts) do
    origin = DPoP.origin(url)

    with {:ok, auth_server} <- resolve_server_as(origin, opts) do
      {:ok, %__MODULE__{auth_server: auth_server}}
    end
  end

  defp resolve_server_as(origin, opts) do
    case ServerMetadata.fetch_authorization_server(origin, opts) do
      {:ok, as_origin} ->
        ServerMetadata.fetch(as_origin, opts)

      {:error, :protected_resource_metadata_not_found} ->
        ServerMetadata.fetch(origin, opts)

      {:error, _} = error ->
        error
    end
  end

  defp check_handle(_doc, nil), do: :ok

  defp check_handle(doc, handle) do
    case DID.get_handle(doc) do
      {:ok, claimed} ->
        if String.downcase(claimed) == String.downcase(handle),
          do: :ok,
          else: {:error, :handle_mismatch}

      {:error, :not_found} ->
        {:error, :handle_mismatch}
    end
  end

  defp pds_endpoint(doc) do
    case DID.get_pds_endpoint(doc) do
      {:ok, pds} -> {:ok, pds}
      {:error, :not_found} -> {:error, :pds_not_found}
    end
  end

  defp check_issuer(%ServerMetadata{issuer: issuer}, expected) do
    if DPoP.origin(issuer) == DPoP.origin(expected),
      do: :ok,
      else: {:error, :subject_pds_authorization_server_mismatch}
  end

  defp did_opts(opts) do
    opts |> Keyword.take([:timeout]) |> Keyword.put(:http_client, http(opts))
  end

  defp http(opts), do: Keyword.get(opts, :http, HTTP)
end
