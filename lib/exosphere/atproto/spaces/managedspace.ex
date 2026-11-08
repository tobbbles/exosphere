defmodule Exosphere.ATProto.Spaces.Managedspace do
  @moduledoc """
  The managing-app check of `com.atproto.managedspace.policy` (proposal 0016,
  "`managedspace`"; atproto `7992095`).

  A managed space defers every access decision to an external managing app:
  the authority asks it `checkUserAccess` — for a read (with the attested
  `client_id`, when one was presented) or for a write (never with a client,
  since `notifyWrite` does not identify the originating app). This is the
  caller side, for authorities and for apps testing their own endpoint; the
  call is authenticated with service auth from the authority, passed as
  `headers: [{"authorization", "Bearer " <> service_jwt}]`.

  Replaces `Spaces.SimpleSpace.check_user_access/5`; upstream moved the method
  from `com.atproto.simplespace` and made `access` a required parameter.
  """

  alias Exosphere.ATProto.Spaces.XRPC

  @doc """
  Ask the managing app at `endpoint` whether to authorize `user` for
  `access` (`:read` or `:write`) in the space
  (`com.atproto.managedspace.checkUserAccess`).

  Option `:client_id` passes the attested client for read checks; it is
  refused for write checks (`{:error, :client_id_on_write}`), which the
  lexicon says carry none.

  Returns `{:ok, boolean}` from the response's `authorized`.
  """
  @spec check_user_access(
          String.t(),
          String.t(),
          String.t(),
          :read | :write,
          keyword(),
          keyword()
        ) ::
          {:ok, boolean()} | {:error, term()}
  def check_user_access(endpoint, space_ref, user, access, auth, opts \\ [])
      when access in [:read, :write] do
    client_id = Keyword.get(opts, :client_id)

    if access == :write and client_id != nil do
      {:error, :client_id_on_write}
    else
      params = %{
        "space" => space_ref,
        "user" => user,
        "access" => Atom.to_string(access),
        "clientId" => client_id
      }

      case XRPC.query(endpoint, "com.atproto.managedspace.checkUserAccess", params, auth, opts) do
        {:ok, %{"authorized" => authorized}} when is_boolean(authorized) -> {:ok, authorized}
        {:ok, _body} -> {:error, :invalid_response}
        error -> error
      end
    end
  end
end
