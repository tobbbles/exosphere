defmodule Exosphere.ATProto.Repo do
  @moduledoc """
  Exosphere.ATProto repository operations for writing records to a user's PDS.

  This module handles authenticated writes to the user's Exosphere.ATProto repository
  using OAuth tokens and DPoP proofs.
  """

  alias Exosphere.ATProto.HTTP
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
