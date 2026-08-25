defmodule Exosphere.OAuth.Session do
  @moduledoc """
  Process wrapper around an `Exosphere.ATProto.OAuth.Session` that keeps the
  session fresh and makes DPoP-signed XRPC calls.

  The GenServer serializes access to the rotating refresh token (concurrent
  refresh attempts would burn it), refreshes eagerly when the access token
  nears expiry, and retries once through a refresh when the server rejects an
  expired token. Use `Exosphere.ATProto.OAuth.Flow` to produce the session,
  then park it here:

      {:ok, session} = Exosphere.ATProto.OAuth.Flow.callback(ctx, params)
      {:ok, pid} = Exosphere.OAuth.Session.start_link(session: session, name: {:via, Registry, ...})

      {:ok, %{"did" => did}} = Exosphere.OAuth.Session.query(pid, "com.atproto.identity.resolveHandle",
        handle: "atproto.com")

  For persistence beyond the process lifetime, serialize with
  `Exosphere.ATProto.OAuth.Session.to_map/1` (e.g. into your database after
  `handle_call` returns, or via the `:on_refresh` callback) and restore with
  `from_map/1`.

  ## Options for `start_link/1`

  - `:session` - the `%Exosphere.ATProto.OAuth.Session{}` (required)
  - `:on_refresh` - `{m, f, a}` or a 1-arity fun invoked with each refreshed
    session, so callers can persist rotated tokens
  - `:name` - GenServer name
  """

  use GenServer

  alias Exosphere.ATProto.OAuth.Session, as: OAuthSession
  alias Exosphere.ATProto.XRPC.Client, as: XRPCClient
  alias Exosphere.ATProto.XRPC.Error, as: XRPCError

  @refresh_errors ["ExpiredToken", "expired_token", "invalid_token"]

  @type server :: GenServer.server()

  # -- Client API -----------------------------------------------------------

  @doc """
  Start a session process.

  Accepts the options listed in the module documentation, or the session
  struct directly.
  """
  @spec start_link(keyword() | OAuthSession.t()) :: GenServer.on_start()
  def start_link(opts) when is_list(opts) do
    {session, opts} = Keyword.pop(opts, :session)

    GenServer.start_link(
      __MODULE__,
      %{session: session, on_refresh: Keyword.get(opts, :on_refresh)},
      opts
    )
  end

  def start_link(%OAuthSession{} = session) do
    GenServer.start_link(__MODULE__, %{session: session, on_refresh: nil}, [])
  end

  @doc """
  The current session struct.
  """
  @spec get(server()) :: OAuthSession.t()
  def get(server), do: GenServer.call(server, :get)

  @doc """
  Refresh now (rotates the refresh token).
  """
  @spec refresh(server()) :: {:ok, OAuthSession.t()} | {:error, term()}
  def refresh(server), do: GenServer.call(server, :refresh)

  @doc """
  An XRPC query (GET) through the session's DPoP-bound client, refreshing
  first when the access token has expired and retrying once through a
  refresh when the server reports an expired token.
  """
  @spec query(server(), String.t(), keyword() | map()) ::
          {:ok, map()} | {:error, term()}
  def query(server, nsid, params \\ []),
    do: GenServer.call(server, {:xrpc, :query, nsid, params})

  @doc """
  An XRPC procedure (POST) through the session's DPoP-bound client, with the
  same refresh handling as `query/3`.
  """
  @spec procedure(server(), String.t(), map()) :: {:ok, map()} | {:error, term()}
  def procedure(server, nsid, body \\ %{}),
    do: GenServer.call(server, {:xrpc, :procedure, nsid, body})

  @doc """
  The XRPC client for the session — a plain data struct, useful for
  `Exosphere.ATProto.Repo` and other direct consumers.
  """
  @spec xrpc_client(OAuthSession.t()) :: XRPCClient.t()
  def xrpc_client(%OAuthSession{} = session) do
    XRPCClient.new(session.pds,
      access_token: session.access_token,
      refresh_token: session.refresh_token,
      dpop: session.dpop_key
    )
  end

  # -- Server ---------------------------------------------------------------

  @impl GenServer
  def init(%{session: %OAuthSession{}} = state), do: {:ok, state}

  def init(_), do: {:stop, :session_required}

  @impl GenServer
  def handle_call(:get, _from, %{session: session} = state), do: {:reply, session, state}

  def handle_call(:refresh, _from, state) do
    case do_refresh(state) do
      {:ok, state} -> {:reply, {:ok, state.session}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:xrpc, kind, nsid, arg}, _from, state) do
    state = maybe_refresh_expired(state)

    case run_xrpc(kind, nsid, arg, state.session) do
      {:error, %XRPCError{error: error}} = failure when error in @refresh_errors ->
        case do_refresh(state) do
          {:ok, state} -> {:reply, run_xrpc(kind, nsid, arg, state.session), state}
          {:error, _reason} -> {:reply, failure, state}
        end

      result ->
        {:reply, result, state}
    end
  end

  defp run_xrpc(:query, nsid, params, session),
    do: session |> xrpc_client() |> XRPCClient.query(nsid, params)

  defp run_xrpc(:procedure, nsid, body, session),
    do: session |> xrpc_client() |> XRPCClient.procedure(nsid, body)

  defp maybe_refresh_expired(%{session: session} = state) do
    if OAuthSession.expired?(session) do
      case do_refresh(state) do
        {:ok, state} -> state
        {:error, _reason} -> state
      end
    else
      state
    end
  end

  defp do_refresh(%{session: session, on_refresh: on_refresh} = state) do
    case OAuthSession.refresh(session) do
      {:ok, refreshed} ->
        notify_refresh(on_refresh, refreshed)
        {:ok, %{state | session: refreshed}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp notify_refresh(nil, _session), do: :ok
  defp notify_refresh(fun, session) when is_function(fun, 1), do: fun.(session)
  defp notify_refresh({m, f, a}, session), do: apply(m, f, a ++ [session])
end
