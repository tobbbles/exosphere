defmodule Exosphere.ATProto.Spaces.Managedspace do
  @moduledoc """
  The managing-app check of `com.atproto.managedspace.policy` (proposal 0016,
  "`managedspace`"; atproto `7992095`).

  A managed space defers access decisions to an external managing app: the
  authority asks it `com.atproto.managedspace.checkAccess` for an account
  (`repo`) — with the attested `client_id` when a read presented one — and
  the app answers `read` and `write` access as independent booleans. This is
  the caller side, for authorities and for apps testing their own endpoint;
  the call is authenticated with service auth from the authority, addressed
  to the managing app's `did#serviceId`.

  Until atproto `atproto-spaces-lexicon-review` (carried by
  `atproto-spaces-cleanup` 4037310) this was `checkUserAccess{user, access}`
  answering a single `authorized`; `check_user_access/6` is replaced by
  `check_access/4`.
  """

  alias Exosphere.ATProto.Spaces.XRPC

  @nsid "com.atproto.managedspace.checkAccess"

  @doc """
  Ask the managing app at `endpoint` for an account's access to the space
  (`com.atproto.managedspace.checkAccess`).

  `auth` is the authority's service auth: `[service_auth: [iss:
  authority_did, aud: managing_app, key: authority_signing_jwk]]` mints it
  per request (`lxm` set for you), or pass pre-minted `headers:`.

  Options:

  - `:repo` — the DID of the account being checked. Omitted for a read with
    no delegation token (an anonymous reader).
  - `:client_id` — the attested OAuth client ID, for reads that presented
    one. Write checks carry none, since a repo update notification does not
    identify the app that made the write.

  Returns `{:ok, %{read: boolean, write: boolean}}`, or
  `{:error, :invalid_response}` when the app's answer lacks either boolean.
  """
  @spec check_access(String.t(), String.t(), keyword(), keyword()) ::
          {:ok, %{read: boolean(), write: boolean()}} | {:error, term()}
  def check_access(endpoint, space_ref, auth, opts \\ []) do
    params = %{
      "space" => space_ref,
      "repo" => Keyword.get(opts, :repo),
      "clientId" => Keyword.get(opts, :client_id)
    }

    case XRPC.query(endpoint, @nsid, params, auth, opts) do
      {:ok, %{"read" => read, "write" => write}} when is_boolean(read) and is_boolean(write) ->
        {:ok, %{read: read, write: write}}

      {:ok, _body} ->
        {:error, :invalid_response}

      error ->
        error
    end
  end
end
