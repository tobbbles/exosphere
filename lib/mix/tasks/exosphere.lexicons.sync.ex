defmodule Mix.Tasks.Exosphere.Lexicons.Sync do
  @shortdoc "Sync vendored lexicons from upstream sources"

  @moduledoc """
  Refreshes the vendored lexicon JSON files under `priv/lexicons` from
  their upstream sources and records the pinned revisions in
  `priv/lexicons/SOURCES.md`.

  Sources:

  - `app/bsky/**`: the full corpus from github.com/bluesky-social/atproto
    at the latest `main` commit (the resolved commit is recorded)
  - `community/**`: full corpus. The file list comes from the GitHub
    mirror (lexicon-community/lexicon); every file downloads from Tangled,
    the canonical source. New community lexicons appear on the next sync.
  - `com/atproto/**`: refresh-in-place. Only the files already vendored
    are re-downloaded, keeping the curated set intentional; new
    com.atproto schemas are added by hand when a generated lexicon needs
    them

  After syncing, run `mix exosphere.gen.bsky` to regenerate modules and
  review the diff.
  """

  use Mix.Task

  @atproto_repo "bluesky-social/atproto"
  @tangled_base "https://tangled.org/lexicon.community/lexicons/raw/main"
  @lexicon_dir "priv/lexicons"

  @impl Mix.Task
  def run(_args) do
    Mix.Task.run("app.start")

    atproto_commit = sync_atproto()

    atproto_com_count =
      sync_atproto_com(
        "https://raw.githubusercontent.com/bluesky-social/atproto/#{atproto_commit}/lexicons"
      )

    community_count = sync_community()
    synced_at = Date.utc_today()
    write_sources_md(atproto_commit, synced_at, atproto_com_count, community_count)

    Mix.shell().info("""
    Synced lexicons.

      bluesky-social/atproto pin: #{atproto_commit}
      tangled.org sync date:     #{synced_at}

    Next: mix exosphere.gen.bsky && git diff
    """)
  end

  defp sync_atproto do
    commit =
      @atproto_repo
      |> gh("commits/main")
      |> Map.fetch!("sha")

    tree =
      @atproto_repo
      |> gh("git/trees/#{commit}?recursive=1")
      |> Map.fetch!("tree")

    count =
      tree
      |> Enum.filter(fn entry ->
        path = entry["path"]
        String.starts_with?(path, "lexicons/app/bsky/") and String.ends_with?(path, ".json")
      end)
      |> Enum.map(fn entry ->
        rel = String.trim_leading(entry["path"], "lexicons/")
        dest = Path.join(@lexicon_dir, rel)

        File.mkdir_p!(Path.dirname(dest))

        body = gh_raw("bluesky-social/atproto/#{commit}/#{entry["path"]}")
        File.write!(dest, body)

        rel
      end)
      |> length()

    Mix.shell().info("atproto: #{count} lexicon files at #{String.slice(commit, 0, 12)}")
    String.slice(commit, 0, 12)
  end

  # Tangled raw endpoints serve individual files (no listing over raw), so
  # the file list comes from the GitHub mirror while every download hits
  # Tangled (the canonical source).
  defp sync_community do
    tree =
      "lexicon-community/lexicon"
      |> gh("git/trees/main?recursive=1")
      |> Map.fetch!("tree")

    files =
      tree
      |> Enum.filter(fn entry ->
        String.starts_with?(entry["path"], "community/") and
          String.ends_with?(entry["path"], ".json")
      end)
      |> Enum.map(fn entry ->
        rel = entry["path"]

        case fetch("#{@tangled_base}/#{rel}") do
          {:ok, body} ->
            dest = Path.join(@lexicon_dir, rel)
            File.mkdir_p!(Path.dirname(dest))
            File.write!(dest, body)
            Mix.shell().info("community: synced #{rel}")
            rel

          :error ->
            Mix.shell().error("community: failed to fetch #{rel} from Tangled; skipped")
            nil
        end
      end)
      |> Enum.reject(&is_nil/1)

    length(files)
  end

  defp sync_atproto_com(refresh_base) do
    refresh_existing("com/atproto/**/*.json", refresh_base)
  end

  defp refresh_existing(glob, base) do
    files =
      @lexicon_dir
      |> Path.join(glob)
      |> Path.wildcard()

    for path <- files do
      rel = Path.relative_to(path, @lexicon_dir)

      case fetch("#{base}/#{rel}") do
        {:ok, body} ->
          File.write!(path, body)
          Mix.shell().info("community: refreshed #{rel}")

        :error ->
          Mix.shell().error("community: failed to refresh #{rel} (left unchanged)")
      end
    end

    length(files)
  end

  defp write_sources_md(commit, date, atproto_com_count, community_count) do
    File.write!(Path.join(@lexicon_dir, "SOURCES.md"), """
    # Lexicon sources

    Vendored lexicon JSON files are snapshots of upstream sources, refreshed
    with `mix exosphere.lexicons.sync`. Regenerate modules with
    `mix exosphere.gen.bsky` after syncing.

    | Path | Source | Pin |
    |------|--------|-----|
    | `app/bsky/**`, `com/atproto/**` | https://github.com/bluesky-social/atproto/tree/main/lexicons | #{commit} |
    | `com/atproto/**` (#{atproto_com_count} files), `community/**` (#{community_count} files) | https://tangled.org/lexicon.community/lexicons/tree/main/community (canonical; github.com/lexicon-community/lexicon is a mirror) | synced #{date} |
    """)
  end

  defp gh(repo, path) do
    Mix.shell().cmd("gh api repos/#{repo}/#{path} > /tmp/exosphere-sync.json", quiet: true)

    case File.read("/tmp/exosphere-sync.json") do
      {:ok, body} -> Jason.decode!(body)
      _ -> Mix.raise("gh api failed for #{repo}/#{path}; is gh authenticated?")
    end
  end

  defp gh_raw(path) do
    fetch!("https://raw.githubusercontent.com/#{path}")
  end

  defp fetch!(url) do
    case fetch(url) do
      {:ok, body} -> body
      :error -> Mix.raise("failed to fetch #{url}")
    end
  end

  defp fetch(url) do
    case :httpc.request(:get, {~c"#{url}", []}, [], body_format: :binary) do
      {:ok, {{_version, 200, _}, _headers, body}} -> {:ok, body}
      _ -> :error
    end
  end
end
