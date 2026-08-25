defmodule Exosphere.ATProto.OAuth.Request do
  @moduledoc """
  DPoP-bound HTTP requests against OAuth endpoints.

  One executor shared by every consumer of a DPoP session — the PAR and
  token requests in `Exosphere.ATProto.OAuth.Flow`, session refresh in
  `Exosphere.ATProto.OAuth.Session`, and XRPC calls — so nonce handling
  (`400 use_dpop_nonce` / `401` with a `DPoP-Nonce` header → store → retry
  once) is implemented exactly once.

  ## Options

  In addition to the `Exosphere.ATProto.HTTP.Behaviour` request options:

  - `:form` - map/keyword of form fields, sent as an
    `application/x-www-form-urlencoded` body
  """

  alias Exosphere.ATProto.HTTP
  alias Exosphere.ATProto.OAuth.DPoP
  alias Exosphere.ATProto.OAuth.DPoP.NonceStore

  @http Application.compile_env(:exosphere, :http_client, HTTP)

  @doc """
  Perform `method url` with a DPoP proof header (and, when `access_token` is
  given, a `DPoP`-scheme Authorization header).

  When the server answers with a nonce challenge, the nonce is stored and
  the request is retried once with a fresh proof.
  """
  @spec authorized(
          module() | nil,
          atom(),
          String.t(),
          keyword(),
          DPoP.private_key(),
          String.t() | nil
        ) ::
          {:ok, HTTP.response()} | {:error, term()}
  def authorized(http, method, url, opts, dpop_key, access_token)

  def authorized(nil, method, url, opts, dpop_key, access_token) do
    authorized(@http, method, url, opts, dpop_key, access_token)
  end

  def authorized(http, method, url, opts, dpop_key, access_token)
      when is_atom(method) and is_binary(url) and is_map(dpop_key) do
    do_authorized(http, method, url, opts, dpop_key, access_token, 0)
  end

  defp do_authorized(http, method, url, opts, dpop_key, access_token, attempts) do
    opts = put_request_opts(opts)

    with {:ok, headers} <- dpop_headers(method, url, dpop_key, access_token, opts) do
      request_opts = opts |> Keyword.put(:headers, headers) |> encode_form()

      case http.request(method, url, request_opts) do
        {:ok, response} ->
          case DPoP.nonce_challenge?(response) do
            nil ->
              remember_nonce(response, url)
              {:ok, response}

            nonce when attempts < 1 ->
              NonceStore.put(DPoP.origin(url), nonce)
              do_authorized(http, method, url, opts, dpop_key, access_token, attempts + 1)

            # A second consecutive challenge means the nonce we echoed was
            # rejected; surface the error response itself.
            _nonce ->
              {:ok, response}
          end

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  # Servers may include the current nonce on successful responses; keeping it
  # spares the next request a challenge round-trip.
  defp remember_nonce(%{headers: headers}, url) do
    case DPoP.nonce_header(headers) do
      nil -> :ok
      nonce -> NonceStore.put(DPoP.origin(url), nonce)
    end
  end

  # A nil :timeout (unset upstream) must not reach the HTTP adapter, where it
  # overrides the adapter's default and crashes transport setup.
  defp put_request_opts(opts) do
    case Keyword.get(opts, :timeout) do
      nil -> Keyword.delete(opts, :timeout)
      _timeout -> opts
    end
  end

  defp dpop_headers(method, url, dpop_key, access_token, opts) do
    proof_opts =
      [nonce: NonceStore.get(DPoP.origin(url)), ath: access_token]
      |> Keyword.reject(fn {_k, v} -> is_nil(v) end)

    with {:ok, proof} <- DPoP.proof(dpop_key, String.upcase(to_string(method)), url, proof_opts) do
      auth_headers =
        if access_token, do: [{"authorization", "DPoP #{access_token}"}], else: []

      {:ok, Keyword.get(opts, :headers, []) ++ auth_headers ++ [{"dpop", proof}]}
    end
  end

  defp encode_form(opts) do
    case Keyword.get(opts, :form) do
      nil ->
        opts

      form ->
        opts
        |> Keyword.delete(:form)
        |> Keyword.put(:body, URI.encode_query(form))
        |> Keyword.put(:content_type, "application/x-www-form-urlencoded")
    end
  end
end
