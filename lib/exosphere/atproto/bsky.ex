defmodule Exosphere.ATProto.Bsky do
  @moduledoc """
  Bluesky API client for app.bsky.* lexicons.

  **Deprecated.** app.bsky endpoints are now generated from vendored
  lexicons. Use the generated modules with an
  `Exosphere.ATProto.XRPC.Client` instead:

      client = Exosphere.ATProto.XRPC.Client.new("https://public.api.bsky.app")
      {:ok, profile} = Exosphere.Bsky.Actor.get_profile(client, actor: "alice.bsky.social")

  Note: app.bsky.* endpoints are served by the Bluesky App View service,
  not the user's PDS. The PDS only handles com.atproto.* endpoints.
  """

  alias Exosphere.ATProto.HTTP

  require Logger

  # The Bluesky App View service URL for app.bsky.* endpoints
  # This is different from the user's PDS which only handles com.atproto.* endpoints
  @bsky_app_view "https://public.api.bsky.app"

  @deprecated "Use Exosphere.Bsky.Actor.get_profile/2 with an XRPC client instead"

  @doc """
  Fetch a user's profile.

  This is a public endpoint that doesn't require authentication.

  ## Parameters

  - `actor` - The DID or handle of the user to fetch

  ## Examples

      {:ok, profile} = Exosphere.ATProto.Bsky.get_profile("did:plc:...")
      # profile = %{
      #   "did" => "did:plc:...",
      #   "handle" => "alice.bsky.social",
      #   "displayName" => "Alice",
      #   "avatar" => "https://...",
      #   ...
      # }
  """
  @spec get_profile(String.t()) :: {:ok, map()} | {:error, term()}
  def get_profile(actor) do
    url = "#{@bsky_app_view}/xrpc/app.bsky.actor.getProfile?actor=#{URI.encode_www_form(actor)}"

    case HTTP.get(url) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %{status: status, body: body}} ->
        Logger.warning("[Bsky] Profile fetch failed: HTTP #{status}, body: #{inspect(body)}")
        {:error, {:http_error, status, body}}

      {:error, reason} ->
        Logger.warning("[Bsky] Profile fetch error: #{inspect(reason)}")
        {:error, reason}
    end
  end
end
