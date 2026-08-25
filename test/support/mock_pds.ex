defmodule Exosphere.Test.MockPDS do
  @moduledoc false

  # A local mock PDS + authorization server implementing the ATProto OAuth
  # profile faithfully enough to e2e-test the client: did:web identity,
  # resource-server + authorization-server metadata, PAR (with nonce
  # challenges), the authorize redirect, PKCE, private_key_jwt client
  # assertions, DPoP proofs (including ath and nonce), token exchange with
  # sub/scope/token_type validation, single-use rotating refresh tokens, and
  # a DPoP-protected XRPC endpoint.
  #
  # It speaks plain HTTP on 127.0.0.1 (allowed for localhost in the spec's
  # local-development profile), needs no extra deps, and runs entirely
  # in-process for tests.

  use GenServer

  alias Exosphere.ATProto.OAuth.{DPoP, JWK, JWS, PKCE}

  defstruct [:pid, :port, :origin]

  @client_assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

  # -- API ------------------------------------------------------------------

  def start(opts \\ []) do
    # Not linked: tests stop the server in on_exit, which runs after the
    # (linked) test process has already exited.
    case GenServer.start(__MODULE__, opts) do
      {:ok, pid} ->
        port = GenServer.call(pid, :port)
        {:ok, %__MODULE__{pid: pid, port: port, origin: "http://localhost:#{port}"}}

      error ->
        error
    end
  end

  def stop(%__MODULE__{pid: pid}), do: GenServer.stop(pid)

  @doc """
  Register a client metadata document served at `/oauth-client-metadata.json`
  (the confidential `client_id` for e2e flows points back at this server).
  """
  def register_client(%__MODULE__{pid: pid}, %{} = doc),
    do: GenServer.call(pid, {:register_client, doc})

  @doc """
  Rotate the server's DPoP nonce, invalidating what clients have cached
  (their next request gets nonce-challenged).
  """
  def rotate_nonce(%__MODULE__{pid: pid}), do: GenServer.call(pid, :rotate_nonce)

  @doc """
  Recorded requests as `%{method: ..., path: ..., headers: ...}` maps, oldest
  first — for asserting what actually hit the wire.
  """
  def requests(%__MODULE__{pid: pid}), do: GenServer.call(pid, :requests) |> Enum.reverse()

  def issuer(%__MODULE__{origin: origin}), do: origin

  @doc """
  The did:web DID hosted by this server (`did:web:localhost:PORT`).
  """
  def did(%__MODULE__{port: port}), do: "did:web:localhost:#{port}"

  # -- GenServer ------------------------------------------------------------

  @impl GenServer
  def init(opts) do
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, packet: :raw, active: false, ip: {127, 0, 0, 1}, backlog: 16])

    {:ok, port} = :inet.port(listen)
    origin = "http://localhost:#{port}"

    state = %{
      listen: listen,
      port: port,
      origin: origin,
      issuer: origin,
      entryway: Keyword.get(opts, :entryway),
      client_doc: nil,
      nonce: "n-" <> random(),
      pars: %{},
      codes: %{},
      tokens: %{},
      refresh_tokens: %{},
      requests: []
    }

    {:ok, state, {:continue, :accept}}
  end

  @impl GenServer
  def handle_continue(:accept, state) do
    me = self()
    {:ok, pid} = Task.start(fn -> accept_loop(state.listen, me) end)
    {:noreply, Map.put(state, :acceptor, pid)}
  end

  @impl GenServer
  def handle_call(:port, _from, %{port: port} = state), do: {:reply, port, state}

  def handle_call({:register_client, doc}, _from, state),
    do: {:reply, :ok, %{state | client_doc: doc}}

  def handle_call(:rotate_nonce, _from, state),
    do: {:reply, :ok, %{state | nonce: "n-" <> random()}}

  def handle_call(:requests, _from, %{requests: requests} = state),
    do: {:reply, requests, state}

  def handle_call({:request, method, path, query, headers, body}, _from, state) do
    state = %{
      state
      | requests: [%{method: method, path: path, headers: headers} | state.requests]
    }

    {status, resp_headers, resp_body, state} =
      route(method, path, query, headers, body, state)

    {:reply, {status, resp_headers, resp_body}, state}
  end

  # -- Routing --------------------------------------------------------------

  defp route("GET", "/.well-known/did.json", _, _, _, state) do
    did = "did:web:localhost:#{state.port}"

    json(
      200,
      %{
        "@context" => ["https://www.w3.org/ns/did/v1"],
        "id" => did,
        "alsoKnownAs" => ["at://localhost:#{state.port}"],
        "service" => [
          %{
            "id" => "#{did}#atproto_pds",
            "type" => "AtprotoPersonalDataServer",
            "serviceEndpoint" => state.origin
          }
        ]
      },
      state
    )
  end

  defp route("GET", "/.well-known/oauth-protected-resource", _, _, _, state) do
    issuer = state.entryway || state.issuer

    json(200, %{"authorization_servers" => [issuer]}, state)
  end

  defp route("GET", "/.well-known/oauth-authorization-server", _, _, _, state) do
    json(200, as_metadata(state), state)
  end

  defp route("GET", "/oauth-client-metadata.json", _, _, _, state) do
    case state.client_doc do
      nil -> json(404, %{"error" => "not_found"}, state)
      doc -> json(200, doc, state)
    end
  end

  defp route("POST", "/par", _, headers, body, state) do
    form = URI.decode_query(body)

    with {:ok, client} <- resolve_client(form, state),
         :ok <- check_client_auth(form, client, state),
         :ok <- check_par_form(form, client),
         {:ok, proof} <- verify_dpop("POST", state.origin <> "/par", headers, state),
         :ok <- check_nonce(proof, state) do
      request_uri = "urn:ietf:params:oauth:request_uri:" <> random()

      state =
        put_in(state, [:pars, request_uri], %{
          form: form,
          client: client,
          dpop_jwk: proof_jwk(proof)
        })

      json(201, %{"request_uri" => request_uri}, [nonce_header(state)], state)
    else
      {:error, :nonce_required} ->
        json(
          400,
          %{"error" => "use_dpop_nonce"},
          [{"dpop-nonce", state.nonce}],
          state
        )

      {:error, reason} ->
        json(400, %{"error" => "invalid_request", "error_description" => inspect(reason)}, state)
    end
  end

  defp route("GET", "/authorize", query, _, _, state) do
    params = URI.decode_query(query)

    with {:ok, par} <- fetch_par(params, state),
         :ok <- check_client_id(params, par) do
      code = "ac-" <> random()
      # With a login_hint the account was chosen up-front (identity flow);
      # without one the "user logged in at the AS" and got this server's
      # own account (server flow).
      sub = par.form["login_hint"] || "did:web:localhost:#{state.port}"

      state =
        put_in(state, [:codes, code], %{
          par: par,
          sub: sub,
          used: false
        })

      redirect =
        par.form["redirect_uri"] <>
          "?" <>
          URI.encode_query(%{
            "code" => code,
            "state" => par.form["state"],
            "iss" => state.issuer
          })

      {302, [{"location", redirect}, nonce_header(state)], "", state}
    else
      {:error, reason} ->
        json(400, %{"error" => "invalid_request", "error_description" => inspect(reason)}, state)
    end
  end

  defp route("POST", "/token", _, headers, body, state) do
    form = URI.decode_query(body)

    case form["grant_type"] do
      "authorization_code" -> token_authorization_code(form, headers, state)
      "refresh_token" -> token_refresh(form, headers, state)
      _ -> json(400, %{"error" => "unsupported_grant_type"}, state)
    end
  end

  defp route("GET", "/xrpc/" <> _nsid = path, _, headers, _, state) do
    with {:ok, token} <- bearer_token(headers),
         {:ok, issued} <- fetch_token(token, state),
         {:ok, proof} <- verify_dpop("GET", state.origin <> path, headers, state),
         :ok <- check_nonce(proof, state),
         :ok <- check_ath(proof, token) do
      json(
        200,
        %{"did" => issued.sub, "handle" => "localhost:#{state.port}", "collections" => []},
        [nonce_header(state)],
        state
      )
    else
      {:error, :nonce_required} ->
        json(400, %{"error" => "use_dpop_nonce"}, [{"dpop-nonce", state.nonce}], state)

      {:error, :invalid_token} ->
        json(401, %{"error" => "invalid_token"}, [], state)

      {:error, reason} ->
        json(400, %{"error" => "invalid_request", "error_description" => inspect(reason)}, state)
    end
  end

  defp route(method, path, _, _, _, state) do
    json(404, %{"error" => "not_found", "path" => path, "method" => method}, state)
  end

  # -- Token grants ---------------------------------------------------------

  defp token_authorization_code(form, headers, state) do
    with {:ok, code} <- fetch_code(form, state),
         {:ok, client} <- check_code_client(form, code, state),
         :ok <- check_code_auth(form, client, state),
         :ok <- check_pkce(form, code),
         {:ok, proof} <- verify_dpop("POST", state.origin <> "/token", headers, state),
         :ok <- check_nonce(proof, state),
         :ok <- check_dpop_binding(proof, code.par.dpop_jwk) do
      issue(code.sub, String.split(code.par.form["scope"]), code.par.dpop_jwk, state)
    else
      {:error, :nonce_required} ->
        json(400, %{"error" => "use_dpop_nonce"}, [{"dpop-nonce", state.nonce}], state)

      {:error, :invalid_grant} ->
        json(400, %{"error" => "invalid_grant"}, [], state)

      {:error, reason} ->
        json(400, %{"error" => "invalid_request", "error_description" => inspect(reason)}, state)
    end
  end

  defp token_refresh(form, headers, state) do
    with {:ok, refresh} <- fetch_refresh(form, state),
         {:ok, proof} <- verify_dpop("POST", state.origin <> "/token", headers, state),
         :ok <- check_nonce(proof, state),
         :ok <- check_dpop_binding(proof, refresh.dpop_jwk) do
      state = put_in(state, [:refresh_tokens, form["refresh_token"], :used], true)
      issue(refresh.sub, refresh.scope, refresh.dpop_jwk, state)
    else
      {:error, :nonce_required} ->
        json(400, %{"error" => "use_dpop_nonce"}, [{"dpop-nonce", state.nonce}], state)

      {:error, :invalid_grant} ->
        json(400, %{"error" => "invalid_grant"}, [], state)

      {:error, reason} ->
        json(400, %{"error" => "invalid_request", "error_description" => inspect(reason)}, state)
    end
  end

  defp issue(sub, scope, dpop_jwk, state) do
    access = "at-" <> random()
    refresh = "rt-" <> random()

    state =
      state
      |> put_in([:tokens, access], %{sub: sub, scope: scope, dpop_jwk: dpop_jwk})
      |> put_in([:refresh_tokens, refresh], %{
        sub: sub,
        scope: scope,
        dpop_jwk: dpop_jwk,
        used: false
      })

    json(
      200,
      %{
        "access_token" => access,
        "refresh_token" => refresh,
        "sub" => sub,
        "scope" => Enum.join(scope, " "),
        "token_type" => "DPoP",
        "expires_in" => 3600
      },
      [nonce_header(state)],
      state
    )
  end

  # -- Validation -----------------------------------------------------------

  defp as_metadata(state) do
    %{
      "issuer" => state.issuer,
      "authorization_endpoint" => state.origin <> "/authorize",
      "token_endpoint" => state.origin <> "/token",
      "pushed_authorization_request_endpoint" => state.origin <> "/par",
      "response_types_supported" => ["code"],
      "grant_types_supported" => ["authorization_code", "refresh_token"],
      "scopes_supported" => ["atproto", "transition:generic"],
      "token_endpoint_auth_methods_supported" => ["none", "private_key_jwt"],
      "token_endpoint_auth_signing_alg_values_supported" => ["ES256"],
      "dpop_signing_alg_values_supported" => ["ES256"],
      "require_pushed_authorization_requests" => true,
      "client_id_metadata_document_supported" => true,
      "authorization_response_iss_parameter_supported" => true
    }
  end

  defp resolve_client(%{"client_id" => client_id}, state)
       when client_id == state.origin <> "/oauth-client-metadata.json" do
    case state.client_doc do
      nil -> {:error, :client_not_registered}
      doc -> {:ok, %{id: client_id, confidential?: true, doc: doc}}
    end
  end

  # The loopback public client: metadata is carried in the client_id query
  defp resolve_client(%{"client_id" => "http://localhost" <> client_query}, _state) do
    params = client_query |> String.trim_leading("?") |> URI.decode_query()

    {:ok,
     %{
       id: "http://localhost" <> client_query,
       confidential?: false,
       doc: %{
         "client_id" => "http://localhost" <> client_query,
         "redirect_uris" => String.split(params["redirect_uri"], " "),
         "scope" => params["scope"]
       }
     }}
  end

  defp resolve_client(_, _), do: {:error, :unknown_client}

  defp check_client_auth(
         %{"client_assertion_type" => @client_assertion_type} = form,
         client,
         state
       ) do
    key = client.doc["jwks"]["keys"] |> List.first()
    now = System.system_time(:second)

    case JWS.verify(key, form["client_assertion"] || "", ["ES256"]) do
      {:ok, claims} ->
        cond do
          claims["iss"] != client.id or claims["sub"] != client.id ->
            {:error, :assertion_subject_mismatch}

          claims["aud"] != state.issuer ->
            {:error, :assertion_audience_mismatch}

          claims["exp"] <= now or claims["iat"] > now + 60 ->
            {:error, :assertion_window}

          true ->
            :ok
        end

      _ ->
        {:error, :assertion_signature}
    end
  end

  defp check_client_auth(_form, %{confidential?: true}, _state),
    do: {:error, :client_assertion_required}

  defp check_client_auth(_form, _client, _state), do: :ok

  defp check_par_form(form, client) do
    login_hint = form["login_hint"]

    cond do
      form["response_type"] != "code" ->
        {:error, :response_type}

      form["code_challenge_method"] != "S256" ->
        {:error, :code_challenge_method}

      not is_map_key(form, "code_challenge") ->
        {:error, :code_challenge_missing}

      not is_map_key(form, "state") ->
        {:error, :state_missing}

      form["redirect_uri"] not in client.doc["redirect_uris"] ->
        {:error, :redirect_uri}

      "atproto" not in String.split(form["scope"]) ->
        {:error, :atproto_scope}

      is_binary(login_hint) and not String.starts_with?(login_hint, "did:") ->
        {:error, :login_hint_did_required}

      true ->
        :ok
    end
  end

  defp fetch_par(%{"request_uri" => request_uri}, state) do
    case Map.fetch(state.pars, request_uri) do
      {:ok, par} -> {:ok, par}
      :error -> {:error, :unknown_request_uri}
    end
  end

  defp fetch_par(_, _), do: {:error, :missing_request_uri}

  defp check_client_id(%{"client_id" => id}, %{form: %{"client_id" => id}}), do: :ok
  defp check_client_id(_, _), do: {:error, :client_id_mismatch}

  defp fetch_code(%{"code" => code}, state) do
    case Map.fetch(state.codes, code) do
      {:ok, %{used: false} = issued} -> {:ok, issued}
      {:ok, %{used: true}} -> {:error, :invalid_grant}
      :error -> {:error, :invalid_grant}
    end
  end

  defp fetch_code(_, _), do: {:error, :invalid_grant}

  defp check_code_client(%{"client_id" => id}, code, state) do
    if code.par.form["client_id"] == id,
      do: resolve_client(%{"client_id" => id}, state),
      else: {:error, :client}
  end

  defp check_code_auth(form, client, state), do: check_client_auth(form, client, state)

  defp check_pkce(%{"code_verifier" => verifier}, code) do
    if PKCE.challenge(verifier) == code.par.form["code_challenge"],
      do: :ok,
      else: {:error, :invalid_grant}
  end

  defp check_pkce(_, _), do: {:error, :invalid_grant}

  defp fetch_refresh(%{"refresh_token" => rt}, state) do
    case Map.fetch(state.refresh_tokens, rt) do
      {:ok, %{used: false} = refresh} -> {:ok, refresh}
      {:ok, %{used: true}} -> {:error, :invalid_grant}
      :error -> {:error, :invalid_grant}
    end
  end

  defp fetch_refresh(_, _), do: {:error, :invalid_grant}

  defp fetch_token("at-" <> _ = token, state) do
    case Map.fetch(state.tokens, token) do
      {:ok, issued} -> {:ok, issued}
      :error -> {:error, :invalid_token}
    end
  end

  defp fetch_token(_, _), do: {:error, :invalid_token}

  defp bearer_token(headers) do
    case List.keyfind(headers, "authorization", 0) do
      {"authorization", "DPoP " <> token} -> {:ok, token}
      _ -> {:error, :invalid_token}
    end
  end

  # Verify a DPoP proof header: signature against its own jwk, htm/htu/iat
  # freshness, and (optionally) nonce and key binding.
  defp verify_dpop(method, url, headers, _state) do
    case List.keyfind(headers, "dpop", 0) do
      {"dpop", proof} ->
        with {:ok, header, claims} <- JWS.decode(proof),
             true <- header["typ"] == "dpop+jwt" || {:error, :dpop_typ},
             true <- header["alg"] in ["ES256", "ES256K"] || {:error, :dpop_alg},
             {:ok, _} <- JWS.verify(header["jwk"], proof, ["ES256", "ES256K"]),
             true <- claims["htm"] == method || {:error, :dpop_htm},
             true <- claims["htu"] == DPoP.normalize_htu(url) || {:error, :dpop_htu},
             now = System.system_time(:second),
             true <-
               (is_integer(claims["iat"]) and abs(now - claims["iat"]) < 300) or
                 {:error, :dpop_iat},
             true <-
               (is_binary(claims["jti"]) and byte_size(claims["jti"]) > 0) or
                 {:error, :dpop_jti} do
          {:ok, %{header: header, claims: claims}}
        else
          {:error, _} = error -> error
        end

      _ ->
        {:error, :dpop_missing}
    end
  end

  defp check_nonce(%{claims: claims}, state) do
    if claims["nonce"] == state.nonce, do: :ok, else: {:error, :nonce_required}
  end

  defp check_ath(%{claims: claims}, token) do
    expected = :crypto.hash(:sha256, token) |> Base.url_encode64(padding: false)
    if claims["ath"] == expected, do: :ok, else: {:error, :ath_mismatch}
  end

  defp check_dpop_binding(%{header: header}, expected_jwk) do
    with {:ok, got} <- JWK.thumbprint(header["jwk"]),
         {:ok, expected} <- JWK.thumbprint(expected_jwk) do
      if got == expected, do: :ok, else: {:error, :dpop_key_changed}
    end
  end

  defp proof_jwk(%{header: %{"jwk" => jwk}}), do: jwk

  # -- HTTP plumbing --------------------------------------------------------

  defp accept_loop(listen, server) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        {:ok, pid} = Task.start(fn -> serve(socket, server) end)
        :ok = :gen_tcp.controlling_process(socket, pid)
        accept_loop(listen, server)

      {:error, :closed} ->
        :ok
    end
  end

  defp serve(socket, server) do
    case read_request(socket) do
      {:ok, method, path, headers, body} ->
        {uri_path, query} = split_path(path)
        reply = GenServer.call(server, {:request, method, uri_path, query, headers, body})

        {status, resp_headers, resp_body} = reply
        send_response(socket, status, resp_headers, resp_body)

      :closed ->
        :ok
    end

    :gen_tcp.close(socket)
  end

  defp read_request(socket, buffer \\ "") do
    case :gen_tcp.recv(socket, 0, 5000) do
      {:ok, data} ->
        buffer = buffer <> data

        case header_end(buffer) do
          :nomatch ->
            read_request(socket, buffer)

          {:ok, head, rest} ->
            with {:ok, method, path} <- request_line(head) do
              body = read_body(socket, rest, content_length(head))
              {:ok, method, path, parse_headers(head), body}
            end
        end

      {:error, _} ->
        :closed
    end
  end

  defp read_body(socket, buffer, target) when byte_size(buffer) < target do
    case :gen_tcp.recv(socket, 0, 5000) do
      {:ok, data} -> read_body(socket, buffer <> data, target)
      {:error, _} -> buffer
    end
  end

  defp read_body(_socket, buffer, target),
    do: binary_part(buffer, 0, min(target, byte_size(buffer)))

  defp content_length(head) do
    case List.keyfind(parse_headers(head), "content-length", 0) do
      {_, value} -> String.to_integer(value)
      nil -> 0
    end
  rescue
    _ -> 0
  end

  defp header_end(buffer) do
    case :binary.match(buffer, "\r\n\r\n") do
      {index, 4} ->
        {:ok, binary_part(buffer, 0, index),
         binary_part(buffer, index + 4, byte_size(buffer) - index - 4)}

      :nomatch ->
        :nomatch
    end
  end

  defp request_line(head) do
    case String.split(head, "\r\n", parts: 2) do
      [line | _] ->
        case String.split(line, " ") do
          [method, path, _version] -> {:ok, method, path}
          _ -> :error
        end

      _ ->
        :error
    end
  end

  defp split_path(path) do
    case String.split(path, "?", parts: 2) do
      [p] -> {p, ""}
      [p, q] -> {p, q}
    end
  end

  defp parse_headers(head) do
    head
    |> String.split("\r\n")
    |> Enum.drop(1)
    |> Enum.flat_map(fn line ->
      case String.split(line, ":", parts: 2) do
        [k, v] -> [{String.downcase(String.trim(k)), String.trim(v)}]
        _ -> []
      end
    end)
  end

  defp send_response(socket, status, headers, body) do
    reason = reason_phrase(status)

    head = [
      "HTTP/1.1 #{status} #{reason}",
      "content-length: #{byte_size(body)}",
      "connection: close"
    ]

    response = Enum.join(head ++ Enum.map(headers, fn {k, v} -> "#{k}: #{v}" end), "\r\n")
    :gen_tcp.send(socket, [response, "\r\n\r\n", body])
  end

  defp reason_phrase(200), do: "OK"
  defp reason_phrase(201), do: "Created"
  defp reason_phrase(302), do: "Found"
  defp reason_phrase(400), do: "Bad Request"
  defp reason_phrase(401), do: "Unauthorized"
  defp reason_phrase(404), do: "Not Found"
  defp reason_phrase(_), do: "Unknown"

  defp json(status, body, state), do: json(status, body, [], state)

  defp json(status, body, headers, state),
    do: {status, [{"content-type", "application/json"}] ++ headers, Jason.encode!(body), state}

  defp nonce_header(state), do: {"dpop-nonce", state.nonce}

  defp random, do: Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
end
