defmodule Mix.Tasks.Exosphere.Gen.Bsky do
  @shortdoc "Deprecated: use mix exosphere.gen.lexicons instead"

  @moduledoc """
  Deprecated alias for `mix exosphere.gen.lexicons`.

  The generator now handles every vendored source (app.bsky and
  community.lexicon) with optional scoping; this task remains so existing
  workflows keep working.
  """

  use Mix.Task

  alias Mix.Tasks.Exosphere.Gen.Lexicons

  @deprecated "Use mix exosphere.gen.lexicons instead"

  @impl Mix.Task
  def run(args) do
    Mix.shell().error(
      "[deprecated] mix exosphere.gen.bsky is renamed; use mix exosphere.gen.lexicons (all sources) " <>
        "or mix exosphere.gen.lexicons app.bsky to scope to app.bsky"
    )

    Lexicons.run(args)
  end
end
