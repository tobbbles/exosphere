defmodule Exosphere.Application do
  @moduledoc """
  Exosphere's supervision tree.

  Starts the shared OAuth infrastructure (`DPoP.NonceStore`). The Hex
  dependency starts this application automatically; if you embed exosphere
  via `extra_applications`, add `:exosphere` to `extra_applications` instead
  of `applications` so the tree still starts under your release's root
  supervisor.
  """

  use Application

  @impl Application
  def start(_type, _args) do
    children = [
      Exosphere.ATProto.OAuth.DPoP.NonceStore
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: Exosphere.Supervisor)
  end
end
