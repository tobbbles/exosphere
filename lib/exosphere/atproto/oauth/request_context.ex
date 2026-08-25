defmodule Exosphere.ATProto.OAuth.RequestContext do
  @moduledoc """
  State an application must retain between the two legs of the authorization
  flow.

  `Flow.authorize_url/3` returns a context next to the authorize URL; the
  caller persists it (Plug session, database, …) keyed by user/session and
  feeds it back into `Flow.callback/3`. It contains secrets (the PKCE
  verifier and the DPoP private key), so it must be stored server-side —
  never in a cookie the browser can read, and never as the OAuth `state`
  itself.

  `to_map/1` / `from_map/1` round-trip the context through plain
  JSON-encodable maps for persistence.
  """

  alias Exosphere.ATProto.OAuth.{Client, ServerMetadata}

  defstruct [
    :state,
    :verifier,
    :redirect_uri,
    :dpop_key,
    :client,
    :auth_server,
    :expected_did,
    :pds
  ]

  @type t :: %__MODULE__{
          state: String.t(),
          verifier: String.t(),
          redirect_uri: String.t(),
          dpop_key: map(),
          client: Client.t(),
          auth_server: ServerMetadata.t(),
          expected_did: String.t() | nil,
          pds: String.t() | nil
        }

  @doc """
  Serialize to a plain, `Jason`-encodable map for persistence.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = ctx) do
    %{
      "state" => ctx.state,
      "verifier" => ctx.verifier,
      "redirect_uri" => ctx.redirect_uri,
      "dpop_key" => ctx.dpop_key,
      "client" => Client.to_map(ctx.client),
      "auth_server" => ServerMetadata.to_map(ctx.auth_server),
      "expected_did" => ctx.expected_did,
      "pds" => ctx.pds
    }
  end

  @doc """
  Rebuild a context serialized with `to_map/1`.
  """
  @spec from_map(map()) :: {:ok, t()} | {:error, :invalid_request_context}
  def from_map(map) when is_map(map) do
    with {:ok, client} <- Client.from_map(map["client"] || %{}),
         {:ok, auth_server} <- ServerMetadata.from_map(map["auth_server"] || %{}) do
      {:ok,
       %__MODULE__{
         state: map["state"],
         verifier: map["verifier"],
         redirect_uri: map["redirect_uri"],
         dpop_key: map["dpop_key"],
         client: client,
         auth_server: auth_server,
         expected_did: map["expected_did"],
         pds: map["pds"]
       }}
    end
  end

  def from_map(_), do: {:error, :invalid_request_context}
end
