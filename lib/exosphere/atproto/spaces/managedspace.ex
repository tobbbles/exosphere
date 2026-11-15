defmodule Exosphere.ATProto.Spaces.Managedspace do
  @moduledoc """
  The managing-app check of `com.atproto.managedspace.policy` (proposal 0016,
  "`managedspace`"; November 12 alpha, atproto `d4def6e`).

  A managed space defers access decisions to an external managing app — the
  policy's `managingApp`, a `did#serviceId` reference. The authority asks it

      GET {endpoint}/xrpc/com.atproto.managedspace.checkAccess?space=…&repo=…&clientId=…
      → {"read": true, "write": false}

  and uses whichever of `read` and `write` it needs: one call answers both.
  `repo` is the account being checked, absent for a read with no delegation
  token (so a managed space asks the app rather than refusing outright — the
  app answers `read: true` there only for spaces meant to be publicly
  readable). `clientId` is the attested OAuth client, sent only when the
  request presented a client attestation; a check prompted by a write carries
  none, since `notifyRepoUpdate` does not identify the app. The authority's
  service auth carries `lxm=com.atproto.managedspace.checkAccess` (`lxm/0`).

  Both halves live here:

  - the authority (caller) side — `check_access/4`;
  - the managing app (callee) side — `decode_check_access/1` to read the
    query, `lxm/0` for `XRPC.ServiceAuth.verify/3`, and
    `check_access_response/2` to answer.

  ## Failing to decide is not a denial

  When the managing app can't be resolved, errors, or doesn't answer within
  10 seconds, the reference space host fails the request with
  `UpstreamFailure` rather than denying access: `authorizeSpaceSync` issues
  no credential but leaves the caller's notify registration in place, and a
  repo host retries its `notifyRepoUpdate` instead of dropping it. A host
  built on `check_access/4` should do the same with every `{:error, _}` it
  returns — including `:invalid_response` — and answer only an
  `{:ok, %{read: false}}` / `{:ok, %{write: false}}` as a refusal.
  `check_access/4` bounds the call at 10 seconds unless given a `:timeout`.

  Until the November 12 alpha this was `checkUserAccess{user, access}`
  answering a single `authorized`.
  """

  alias Exosphere.ATProto.Identity.DID
  alias Exosphere.ATProto.Spaces.XRPC

  @nsid "com.atproto.managedspace.checkAccess"
  @default_timeout 10_000

  @typedoc "A decoded `checkAccess` query, as the managing app sees it."
  @type request :: %{space: String.t(), repo: String.t() | nil, client_id: String.t() | nil}

  @doc """
  The method's NSID, which is also the `lxm` of the authority's service auth:
  `"com.atproto.managedspace.checkAccess"`. A managing app verifies incoming
  calls with `XRPC.ServiceAuth.verify(jwt, get_key, aud: "did:…#serviceId",
  lxm: Managedspace.lxm())`.
  """
  @spec lxm() :: String.t()
  def lxm, do: @nsid

  @doc """
  Ask the managing app at `endpoint` for an account's access to the space
  (`com.atproto.managedspace.checkAccess`).

  `auth` is the authority's service auth: `[service_auth: [iss:
  authority_did, aud: managing_app, key: authority_signing_jwk]]` mints it
  per request (`lxm` set for you), or pass pre-minted `headers:`. `aud` is
  the policy's `managingApp` reference itself.

  Options:

  - `:repo` — the DID of the account being checked. Omit it for a read with
    no delegation token (an anonymous reader).
  - `:client_id` — the attested OAuth client ID, for reads that presented
    one. Write checks carry none.
  - `:timeout` — defaults to 10 seconds, the reference host's bound.

  Returns `{:ok, %{read: boolean, write: boolean}}`, or
  `{:error, :invalid_response}` when the app's answer lacks either boolean.
  Treat any error as `UpstreamFailure`, not as a denial (see the moduledoc).
  """
  @spec check_access(String.t(), String.t(), keyword(), keyword()) ::
          {:ok, %{read: boolean(), write: boolean()}} | {:error, term()}
  def check_access(endpoint, space_ref, auth, opts \\ []) do
    params = %{
      "space" => space_ref,
      "repo" => Keyword.get(opts, :repo),
      "clientId" => Keyword.get(opts, :client_id)
    }

    opts = Keyword.put_new(opts, :timeout, @default_timeout)

    case XRPC.query(endpoint, @nsid, params, auth, opts) do
      {:ok, %{"read" => read, "write" => write}} when is_boolean(read) and is_boolean(write) ->
        {:ok, %{read: read, write: write}}

      {:ok, _body} ->
        {:error, :invalid_response}

      error ->
        error
    end
  end

  @doc """
  Decode a `checkAccess` query on the managing app's side, from its
  (string-keyed) query parameters: `{:ok, %{space:, repo:, client_id:}}`,
  with `repo` and `client_id` `nil` when absent.

  `space` must be a space ref, `repo` a DID and `clientId` a URI; anything
  else is `{:error, :invalid_request}`. Checking the service auth — that it
  is from the space's authority, addressed to this app's `did#serviceId`,
  with `lxm/0` — is the caller's, before this.
  """
  @spec decode_check_access(map()) :: {:ok, request()} | {:error, :invalid_request}
  def decode_check_access(%{"space" => space} = params) do
    repo = Map.get(params, "repo")
    client_id = Map.get(params, "clientId")

    if XRPC.space_ref?(space) and (is_nil(repo) or DID.valid?(repo)) and
         (is_nil(client_id) or XRPC.uri?(client_id)),
       do: {:ok, %{space: space, repo: repo, client_id: client_id}},
       else: {:error, :invalid_request}
  end

  def decode_check_access(_), do: {:error, :invalid_request}

  @doc """
  The managing app's answer, in its wire shape: `%{"read" => read, "write" =>
  write}`. Both are required; answer `read: true` without a `repo` only for a
  space meant to be publicly readable.
  """
  @spec check_access_response(boolean(), boolean()) :: %{String.t() => boolean()}
  def check_access_response(read, write) when is_boolean(read) and is_boolean(write),
    do: %{"read" => read, "write" => write}
end
