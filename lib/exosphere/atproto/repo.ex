defmodule Exosphere.ATProto.Repo do
  @moduledoc """
  Exosphere.ATProto repository operations for writing records to a user's PDS.

  This module handles authenticated writes to the user's Exosphere.ATProto repository
  using OAuth tokens and DPoP proofs.
  """

  alias Exosphere.ATProto.{CAR, CID, HTTP, Identity.DID, Repo.Commit}
  require Logger

  @doc """
  Put (create or update) a record in the user's repository.

  Uses `com.atproto.repo.putRecord` for records with known keys (like profile with "self").

  ## Parameters

  - `session` - OAuth session with access_token and dpop_private_key
  - `pds_url` - URL of the user's PDS
  - `did` - The user's DID
  - `collection` - The collection NSID (e.g., "app.bsky.actor.profile")
  - `rkey` - The record key (e.g., "self")
  - `record` - The record data to write

  ## Returns

  - `{:ok, %{uri: uri, cid: cid}}` on success
  - `{:error, reason}` on failure
  """
  def put_record(session, pds_url, did, collection, rkey, record) do
    url = "#{pds_url}/xrpc/com.atproto.repo.putRecord"

    body = %{
      "repo" => did,
      "collection" => collection,
      "rkey" => rkey,
      "record" => add_type(record, collection)
    }

    make_authenticated_request(url, body, session)
  end

  @doc """
  Create a new record in the user's repository.

  Uses `com.atproto.repo.createRecord` for records with auto-generated keys.

  ## Parameters

  - `session` - OAuth session with access_token and dpop_private_key
  - `pds_url` - URL of the user's PDS
  - `did` - The user's DID
  - `collection` - The collection NSID
  - `record` - The record data to write

  ## Returns

  - `{:ok, %{uri: uri, cid: cid}}` on success
  - `{:error, reason}` on failure
  """
  def create_record(session, pds_url, did, collection, record) do
    url = "#{pds_url}/xrpc/com.atproto.repo.createRecord"

    body = %{
      "repo" => did,
      "collection" => collection,
      "record" => add_type(record, collection)
    }

    make_authenticated_request(url, body, session)
  end

  @doc """
  Delete a record from the user's repository.

  ## Parameters

  - `session` - OAuth session
  - `pds_url` - URL of the user's PDS
  - `did` - The user's DID
  - `collection` - The collection NSID
  - `rkey` - The record key to delete
  """
  def delete_record(session, pds_url, did, collection, rkey) do
    url = "#{pds_url}/xrpc/com.atproto.repo.deleteRecord"

    body = %{
      "repo" => did,
      "collection" => collection,
      "rkey" => rkey
    }

    make_authenticated_request(url, body, session)
  end

  @doc """
  Fetch a repository from a PDS as a CAR archive and fully verify it.

  Downloads `com.atproto.sync.getRepo`, reads the record set out of the
  returned MST, checks it against the commit's signed root
  (`Repo.Commit.verify_checkout/2`), resolves the repo's DID document, and
  verifies the commit signature (`Repo.Commit.verify/3`).

  This is the trustless read path: rather than trusting the PDS's `getRecord`
  responses, the whole repository is checked against the key the account
  advertises in its DID document.

  ## Parameters

  - `pds_url` - Base URL of the PDS (e.g. `"https://bsky.social"`)
  - `did` - The repository's DID
  - `opts` - Options:
    - `:verify_signature` - When `false`, skip DID resolution and signature
      verification (default: `true`)
    - `:http` - HTTP client module implementing `HTTP.Behaviour` (default:
      `HTTP`; useful for testing)
    - `:did_document` - A pre-resolved `%Identity.Document{}` to verify
      against, skipping DID resolution (useful for testing)

  ## Returns

  - `{:ok, %{did: did, rev: rev, commit: %CID{}, records: %{path => %CID{}}}}`
  - `{:error, reason}` — network errors, malformed CAR, MST/root mismatches,
    or signature failures
  """
  @spec verify_checkout(String.t(), DID.did(), keyword()) ::
          {:ok, %{did: DID.did(), rev: String.t() | nil, commit: CID.t(), records: map()}}
          | {:error, term()}
  def verify_checkout(pds_url, did, opts \\ []) do
    http = Keyword.get(opts, :http, HTTP)

    with {:ok, car} <- fetch_repo_car(http, pds_url, did),
         {:ok, commit_cid, commit, blocks} <- root_commit(car),
         {:ok, records} <- Commit.verify_checkout(commit, blocks),
         :ok <- maybe_verify_signature(commit, did, opts) do
      {:ok, %{did: did, rev: Map.get(commit, "rev"), commit: commit_cid, records: records}}
    end
  end

  defp fetch_repo_car(http, pds_url, did) do
    url = "#{pds_url}/xrpc/com.atproto.sync.getRepo?" <> URI.encode_query(%{"did" => did})

    case http.get(url) do
      {:ok, %{status: 200, body: body}} when is_binary(body) ->
        {:ok, body}

      {:ok, %{status: status}} ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # A repository CAR has exactly one root: the top commit block, which is
  # itself included among the blocks.
  defp root_commit(car) do
    with {:ok, %{roots: roots, blocks: blocks}} <- CAR.decode_full(car) do
      case roots do
        [%CID{} = commit_cid] ->
          case Map.get(blocks, commit_cid) do
            commit when is_map(commit) -> {:ok, commit_cid, commit, blocks}
            _ -> {:error, {:missing_block, commit_cid}}
          end

        _ ->
          {:error, :no_root}
      end
    end
  end

  defp maybe_verify_signature(commit, did, opts) do
    cond do
      Keyword.get(opts, :verify_signature, true) == false ->
        :ok

      doc = Keyword.get(opts, :did_document) ->
        Commit.verify_with_document(commit, doc)

      true ->
        with {:ok, doc} <- DID.resolve(did) do
          Commit.verify_with_document(commit, doc)
        end
    end
  end

  @doc """
  Get a record from any repository (public, no auth needed).
  """
  def get_record(pds_url, did, collection, rkey) do
    url = "#{pds_url}/xrpc/com.atproto.repo.getRecord"

    query =
      URI.encode_query(%{
        "repo" => did,
        "collection" => collection,
        "rkey" => rkey
      })

    case HTTP.get("#{url}?#{query}") do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        {:error, {:http_error, status, body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Make an authenticated request with DPoP proof
  defp make_authenticated_request(url, body, session, nonce \\ nil, retry_count \\ 0)

  defp make_authenticated_request(_url, _body, _session, _nonce, retry_count)
       when retry_count > 2 do
    Logger.error("[Exosphere.ATProto.Repo] Request failed after max retries")
    {:error, :max_retries}
  end

  defp make_authenticated_request(url, body, session, nonce, retry_count) do
    with {:ok, dpop_key} <- decode_dpop_key(session.dpop_private_key) do
      method_str = "POST"
      dpop_proof = create_dpop_proof(dpop_key, method_str, url, nonce, session.access_token)

      headers = [
        {"authorization", "DPoP #{session.access_token}"},
        {"dpop", dpop_proof}
      ]

      result =
        HTTP.post(url, headers: headers, json: body)

      case result do
        {:ok, %{status: 200, body: response}} ->
          Logger.debug("[Exosphere.ATProto.Repo] Request successful")
          {:ok, response}

        {:ok, %{status: 400, body: %{"error" => "use_dpop_nonce"}, headers: resp_headers}} ->
          # Server requires nonce - extract and retry
          new_nonce = get_dpop_nonce_header(resp_headers)

          if new_nonce do
            Logger.debug("[Exosphere.ATProto.Repo] DPoP nonce required, retrying")
            make_authenticated_request(url, body, session, new_nonce, retry_count + 1)
          else
            Logger.error("[Exosphere.ATProto.Repo] Nonce required but not provided")
            {:error, :nonce_required}
          end

        {:ok, %{status: 401, headers: resp_headers} = response} ->
          # Might need a nonce
          new_nonce = get_dpop_nonce_header(resp_headers)

          if new_nonce && retry_count == 0 do
            Logger.debug("[Exosphere.ATProto.Repo] Got nonce from 401, retrying")
            make_authenticated_request(url, body, session, new_nonce, retry_count + 1)
          else
            Logger.error("[Exosphere.ATProto.Repo] Unauthorized: #{inspect(response.body)}")
            {:error, {:unauthorized, response.body}}
          end

        {:ok, %{status: status, body: response_body}} ->
          Logger.error(
            "[Exosphere.ATProto.Repo] Request failed: HTTP #{status}, #{inspect(response_body)}"
          )

          {:error, {:http_error, status, response_body}}

        {:error, reason} ->
          Logger.error("[Exosphere.ATProto.Repo] Request error: #{inspect(reason)}")
          {:error, reason}
      end
    end
  end

  # Add $type field to record
  defp add_type(record, collection) do
    Map.put(record, "$type", collection)
  end

  # Decode DPoP key from base64-encoded JSON
  defp decode_dpop_key(encoded) do
    with {:ok, json} <- Base.decode64(encoded),
         {:ok, map} <- Jason.decode(json) do
      {:ok, JOSE.JWK.from_map(map)}
    else
      _ -> {:error, :invalid_dpop_key}
    end
  end

  # Create DPoP proof with optional access token hash
  defp create_dpop_proof(dpop_key, method, url, nonce, access_token) do
    uri = URI.parse(url)

    htu =
      "#{uri.scheme}://#{uri.host}#{case uri.port do
        80 -> ""
        443 -> ""
        port -> ":#{port}"
      end}#{uri.path}"

    # Base claims
    claims = %{
      "jti" => generate_jti(),
      "htm" => method,
      "htu" => htu,
      "iat" => System.system_time(:second)
    }

    # Add nonce if provided
    claims = if nonce, do: Map.put(claims, "nonce", nonce), else: claims

    # Add access token hash if provided (for resource server requests)
    claims =
      if access_token do
        ath = :crypto.hash(:sha256, access_token) |> Base.url_encode64(padding: false)
        Map.put(claims, "ath", ath)
      else
        claims
      end

    # Get the public key for the header
    {_, public_map} = JOSE.JWK.to_public(dpop_key) |> JOSE.JWK.to_map()

    header = %{
      "typ" => "dpop+jwt",
      "alg" => "ES256",
      "jwk" => public_map
    }

    {_, jwt} = JOSE.JWT.sign(dpop_key, header, claims) |> JOSE.JWS.compact()
    jwt
  end

  defp generate_jti do
    :crypto.strong_rand_bytes(16)
    |> Base.url_encode64(padding: false)
  end

  # Extract DPoP-Nonce header from response
  defp get_dpop_nonce_header(headers) do
    Enum.find_value(headers, fn
      {"dpop-nonce", value} -> value
      {key, value} when is_binary(key) -> if String.downcase(key) == "dpop-nonce", do: value
      _ -> nil
    end)
  end
end
