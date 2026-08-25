defmodule Exosphere.Test.Interop do
  @moduledoc """
  Helpers for the AT Protocol interop conformance fixtures.

  Fixtures are a vendored, pinned snapshot of
  [`bluesky-social/atproto-interop-tests`](https://github.com/bluesky-social/atproto-interop-tests)
  (CC0). See `test/fixtures/interop/SOURCE.md` for the pinned commit.
  """

  @root Path.join([__DIR__, "..", "fixtures", "interop"])

  @doc "Absolute path to a fixture file relative to the interop root."
  def path(relative), do: Path.expand(Path.join(@root, relative))

  @doc """
  Read a syntax fixture (`*.txt`) into a list of test strings.

  Blank lines and `#` comment lines are dropped. Remaining lines are returned
  verbatim (leading/trailing spaces preserved, since whitespace can be
  significant in some cases).
  """
  @spec lines(String.t()) :: [String.t()]
  def lines(relative) do
    relative
    |> path()
    |> File.read!()
    |> String.split("\n")
    |> Enum.reject(fn line ->
      trimmed = String.trim(line)
      trimmed == "" or String.starts_with?(trimmed, "#")
    end)
  end

  @doc "Read and JSON-decode a fixture file."
  @spec json(String.t()) :: term()
  def json(relative) do
    relative
    |> path()
    |> File.read!()
    |> Jason.decode!()
  end
end
