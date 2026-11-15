defmodule Exosphere.SpecPinsTest do
  @moduledoc """
  Re-verify the Spaces spec pins against the alpha lexicons.

  The Spaces branches pin their cross-checks to a point in a moving spec, and
  "re-verify the pins before promoting anything" has been a manual checklist
  item. This makes it runnable: it fetches the space lexicons from the atproto
  repository and checks, mechanically, that the space namespaces hold exactly
  the methods this library knows, that every method it calls still exists,
  and that every parameter it sends is still a property that method accepts.

  By default it reads the pinned commit, so a pass means the client matches
  what it claims to follow. Set `EXOSPHERE_SPEC_PINS_REF` to a branch (e.g.
  `permissioned-data`) to see how far the client is from where that branch is
  now.

  Excluded from the default run (it needs the network). Opt in with:

      mix test --only external

  A failure here is information, not a bug: the alpha moved, and the client
  needs to move with it. Read the diff before changing code.
  """

  use ExUnit.Case, async: true

  alias Exosphere.ATProto.HTTP
  alias Exosphere.ATProto.Spaces.Policy

  @moduletag :external
  @moduletag timeout: 120_000

  # What `spaces/beta` follows: the November 12 alpha, the surface the Spaces
  # public beta launches on. atproto branch `permissioned-data` at d4def6e,
  # the merged implementation the November 12 migration notes name as the
  # reference (the branch's later commits up to 16bfeba, 2026-11-13, leave
  # the lexicons untouched).
  @pinned_commit "d4def6e9f521896ed8222f576d54923d00b5fbeb"
  @pinned_branch "permissioned-data"

  # The complete lexicon set of the space namespaces at the pin: every method
  # (and the defs, policy and record documents beside them). A method added
  # or removed upstream fails `the space namespaces hold exactly …` below.
  @namespaces %{
    "com.atproto.space" =>
      ~w(applyWrites authorizeSpaceSync clearRecords confirmRegistration createRecord
         createSpace deleteRecord deleteSpace exportSpaceMeta getBlob getDelegationToken
         getLatestCommit getRecord getRepo getSpace importRepo importSpaceMeta listBlobs
         listRecords listRepoOps listSpaces listWriters notifyCredentialsRevoked
         notifyRepoUpdate notifySpaceUpdate putRecord removeWriter updateSpace),
    "com.atproto.memberspace" => ~w(listMembers putMembers removeMembers),
    "com.atproto.managedspace" => ~w(checkAccess),
    "com.atproto.personalspace" => []
  }

  # The non-method documents in those namespaces.
  @documents %{
    "com.atproto.space" => ~w(defs policy),
    "com.atproto.memberspace" => ~w(defs member policy),
    "com.atproto.managedspace" => ~w(policy),
    "com.atproto.personalspace" => ~w(policy)
  }

  # Every space method this library calls, with the parameters it sends. Kept
  # here by hand rather than derived from the source: the point is to state
  # what we believe the wire contract to be, and have the lexicon disagree.
  # The notification methods are called by hosts: notifyRepoUpdate by a repo
  # host, confirmRegistration and notifySpaceUpdate by a space host on a
  # syncer, notifyCredentialsRevoked by a space host on a repo host.
  @calls [
    {"com.atproto.space.getDelegationToken", :query, ["space"]},
    {"com.atproto.space.authorizeSpaceSync", :procedure,
     ["space", "credentialKey", "delegationToken", "clientAttestation", "notify"]},
    {"com.atproto.space.listWriters", :query, ["space", "limit", "cursor"]},
    {"com.atproto.space.getLatestCommit", :query, ["space", "repo"]},
    {"com.atproto.space.listRepoOps", :query,
     ["space", "repo", "since", "cursor", "limit", "excludeValues"]},
    {"com.atproto.space.listRecords", :query,
     ["space", "repo", "collection", "cursor", "limit", "excludeValues"]},
    {"com.atproto.space.getRecord", :query, ["space", "repo", "collection", "rkey"]},
    {"com.atproto.space.getRepo", :query, ["space", "repo"]},
    {"com.atproto.space.notifyRepoUpdate", :procedure, ["space", "repo", "repoRev", "data"]},
    {"com.atproto.space.confirmRegistration", :procedure, ["space", "token", "challenge"]},
    {"com.atproto.space.notifySpaceUpdate", :procedure, ["space", "token", "update"]},
    {"com.atproto.space.notifyCredentialsRevoked", :procedure, ["space", "credentials"]},
    {"com.atproto.space.createRecord", :procedure, ["space", "collection", "rkey", "record"]},
    {"com.atproto.space.putRecord", :procedure, ["space", "collection", "rkey", "record"]},
    {"com.atproto.space.deleteRecord", :procedure, ["space", "collection", "rkey"]},
    {"com.atproto.space.applyWrites", :procedure, ["space", "writes"]},
    {"com.atproto.space.clearRecords", :procedure, ["space", "repo"]},
    {"com.atproto.space.importRepo", :procedure, []},
    {"com.atproto.space.createSpace", :procedure, ["spaceType", "skey", "policy"]},
    {"com.atproto.space.updateSpace", :procedure, ["space", "policy"]},
    {"com.atproto.space.deleteSpace", :procedure, ["space"]},
    {"com.atproto.space.getSpace", :query, ["space"]},
    {"com.atproto.space.listSpaces", :query, ["spaceType", "spaceDid", "limit", "cursor"]},
    {"com.atproto.space.removeWriter", :procedure, ["space", "repo"]},
    {"com.atproto.space.exportSpaceMeta", :query, ["space"]},
    {"com.atproto.space.importSpaceMeta", :procedure, []},
    {"com.atproto.memberspace.putMembers", :procedure, ["space", "members"]},
    {"com.atproto.memberspace.removeMembers", :procedure, ["space", "dids"]},
    {"com.atproto.memberspace.listMembers", :query, ["space", "limit", "cursor"]},
    {"com.atproto.managedspace.checkAccess", :query, ["space", "repo", "clientId"]}
  ]

  # Methods whose bodies this library decodes (a host or syncer receives
  # them), with the fields it requires.
  @received [
    {"com.atproto.space.notifyRepoUpdate", ["space", "repo", "repoRev", "data"]},
    {"com.atproto.space.notifySpaceUpdate", ["space", "token", "update"]},
    {"com.atproto.space.confirmRegistration", ["space", "token", "challenge"]},
    {"com.atproto.space.authorizeSpaceSync", ["space", "credentialKey"]},
    {"com.atproto.space.notifyCredentialsRevoked", ["space", "credentials"]}
  ]

  # The methods that carry STAR archives, and in which direction.
  @star_methods [
    {"com.atproto.space.getRepo", "output"},
    {"com.atproto.space.exportSpaceMeta", "output"},
    {"com.atproto.space.importRepo", "input"},
    {"com.atproto.space.importSpaceMeta", "input"}
  ]

  defp ref, do: System.get_env("EXOSPHERE_SPEC_PINS_REF") || @pinned_commit
  defp raw, do: "https://raw.githubusercontent.com/bluesky-social/atproto/#{ref()}/lexicons"

  test "every space method this library calls still exists, with the parameters it sends" do
    drift =
      Enum.flat_map(@calls, fn {nsid, kind, params} ->
        case fetch_lexicon(nsid) do
          {:ok, lexicon} -> check_call(nsid, kind, params, lexicon)
          {:error, reason} -> ["#{nsid}: could not fetch (#{inspect(reason)})"]
        end
      end)

    assert drift == [],
           """
           The Spaces alpha lexicons have drifted from what this client sends.

           Pinned at atproto #{@pinned_branch} #{@pinned_commit}; checked against #{ref()}.

           #{Enum.map_join(drift, "\n", &("  - " <> &1))}
           """
  end

  test "the space namespaces hold exactly the methods this library knows" do
    drift =
      Enum.flat_map(@namespaces, fn {namespace, methods} ->
        expected = Enum.sort(methods ++ Map.fetch!(@documents, namespace))

        case list_namespace(namespace) do
          {:ok, ^expected} ->
            []

          {:ok, actual} ->
            added = actual -- expected
            removed = expected -- actual
            ["#{namespace}: added #{inspect(added)}, removed #{inspect(removed)}"]

          {:error, reason} ->
            ["#{namespace}: could not list (#{inspect(reason)})"]
        end
      end)

    assert drift == [], "The space namespaces changed:\n" <> Enum.join(drift, "\n")
  end

  test "the writer set entries this library reads are still defs#repoWrite and defs#repoRemoved" do
    # The parameter check only sees what we *send*. `Sync.list_writers/4` and
    # `Sync.decode_space_update/1` also *read* named fields, and a rename there
    # is silent on our side. It has happened four times (`rev` → `repoRev` +
    # `spaceRev`, `hash` → `data`, `did` → `repo`, and the entry becoming a
    # `$type`d union), so it is checked.
    assert {:ok, defs} = fetch_lexicon("com.atproto.space.defs")
    write = get_in(defs, ["defs", "repoWrite"])
    removed = get_in(defs, ["defs", "repoRemoved"])

    assert Enum.sort(write["required"]) == ~w(data repo repoRev spaceRev)
    assert write["properties"]["data"]["type"] == "bytes"
    assert Map.has_key?(write["properties"], "prevSpaceRev")
    assert Enum.sort(removed["required"]) == ~w(repo spaceRev)
    assert Map.has_key?(removed["properties"], "prevSpaceRev")

    assert {:ok, list} = fetch_lexicon("com.atproto.space.listWriters")
    items = get_in(list, ["defs", "main", "output", "schema", "properties", "repos", "items"])
    assert items["type"] == "union"

    assert Enum.sort(items["refs"]) ==
             ["com.atproto.space.defs#repoRemoved", "com.atproto.space.defs#repoWrite"]
  end

  test "the bodies this library decodes still require what it reads" do
    for {nsid, fields} <- @received do
      assert {:ok, lexicon} = fetch_lexicon(nsid)
      required = get_in(lexicon, ["defs", "main", "input", "schema", "required"]) || []

      for field <- fields do
        assert field in required, "#{nsid} no longer requires `#{field}`, which we decode"
      end
    end
  end

  test "notifySpaceUpdate's updates are the four this library matches, by full $type" do
    assert {:ok, lexicon} = fetch_lexicon("com.atproto.space.notifySpaceUpdate")
    update = get_in(lexicon, ["defs", "main", "input", "schema", "properties", "update"])

    assert Enum.sort(update["refs"]) ==
             Enum.sort([
               "com.atproto.space.defs#repoWrite",
               "com.atproto.space.defs#repoRemoved",
               "#spaceDeleted",
               "#registrationExpired"
             ])

    assert get_in(lexicon, ["defs", "registrationExpired", "required"]) == ["spaceRev"]
    assert get_in(lexicon, ["defs", "spaceDeleted", "properties"]) == %{}
  end

  test "confirmRegistration echoes the challenge" do
    assert {:ok, lexicon} = fetch_lexicon("com.atproto.space.confirmRegistration")
    assert get_in(lexicon, ["defs", "main", "output", "schema", "required"]) == ["challenge"]
  end

  test "listRepoOps returns a commit on every page, and RepoNotFound for a never-written repo" do
    assert {:ok, lexicon} = fetch_lexicon("com.atproto.space.listRepoOps")
    main = get_in(lexicon, ["defs", "main"])
    assert "commit" in get_in(main, ["output", "schema", "required"])

    errors = Enum.map(main["errors"], & &1["name"])
    assert "RepoNotFound" in errors
    assert "InvalidSpaceMac" in errors
  end

  test "the MAC'd methods declare InvalidSpaceMac" do
    for nsid <- ~w(getLatestCommit getRecord getRepo listRepoOps) do
      assert {:ok, lexicon} = fetch_lexicon("com.atproto.space." <> nsid)
      errors = Enum.map(get_in(lexicon, ["defs", "main", "errors"]), & &1["name"])
      assert "InvalidSpaceMac" in errors, "#{nsid} no longer declares InvalidSpaceMac"
    end
  end

  test "checkAccess still answers read and write, and putMembers takes defs#member" do
    assert {:ok, check} = fetch_lexicon("com.atproto.managedspace.checkAccess")
    output = get_in(check, ["defs", "main", "output", "schema"])
    assert Enum.sort(output["required"]) == ["read", "write"]

    assert {:ok, defs} = fetch_lexicon("com.atproto.memberspace.defs")
    member = get_in(defs, ["defs", "member"])
    assert Enum.sort(member["required"]) == ["did", "read", "write"]

    assert {:ok, put} = fetch_lexicon("com.atproto.memberspace.putMembers")

    assert get_in(put, [
             "defs",
             "main",
             "input",
             "schema",
             "properties",
             "members",
             "items",
             "ref"
           ]) ==
             "com.atproto.memberspace.defs#member"
  end

  test "notifyRepoUpdate is service-authed, listWriters credential-authed" do
    # Auth lives in prose, not schema: the descriptions are what upstream
    # publishes about it.
    assert {:ok, notify} = fetch_lexicon("com.atproto.space.notifyRepoUpdate")
    assert get_in(notify, ["defs", "main", "description"]) =~ "service auth"

    assert {:ok, list} = fetch_lexicon("com.atproto.space.listWriters")
    assert get_in(list, ["defs", "main", "description"]) =~ "space credential"
  end

  test "STAR archives travel as application/vnd.dasl.star" do
    for {nsid, direction} <- @star_methods do
      assert {:ok, lexicon} = fetch_lexicon(nsid)

      assert get_in(lexicon, ["defs", "main", direction, "encoding"]) ==
               "application/vnd.dasl.star",
             "#{nsid}'s #{direction} encoding changed"
    end
  end

  test "the commit fields this library reads are still the ones defs#commit requires" do
    assert {:ok, lexicon} = fetch_lexicon("com.atproto.space.defs")
    commit = get_in(lexicon, ["defs", "commit"])

    assert Enum.sort(commit["required"]) == Enum.sort(~w(ver repo space rev data)),
           "com.atproto.space.defs#commit changed shape: #{inspect(commit["required"])}"

    assert commit["properties"]["data"]["type"] == "bytes"
  end

  test "the policy union still names the three baseline policies" do
    assert {:ok, lexicon} = fetch_lexicon("com.atproto.space.createSpace")
    refs = get_in(lexicon, ["defs", "main", "input", "schema", "properties", "policy", "refs"])

    assert Enum.sort(refs) == Enum.sort(Policy.baseline_types())
  end

  test "the LtHash parameters in the proposal still match the implementation" do
    # `Spaces.Lthash` hard-codes 1024 little-endian u16 lanes and a 2048-byte
    # BLAKE3 expansion per element. Those numbers live in prose, not a lexicon,
    # so this reads the proposal and checks the words are still there.
    assert {:ok, %{status: 200, body: readme}} =
             HTTP.get(
               "https://raw.githubusercontent.com/bluesky-social/proposals/main/0016-permissioned-data/README.md"
             )

    assert readme =~ "2048",
           "the proposal no longer mentions the 2048-byte state — re-read the commit digest section"

    assert readme =~ ~r/sha256\(state\)/,
           "the commit digest is no longer sha256 over the lane state"
  end

  # The lexicon documents in a namespace directory at the ref, by name, from
  # the GitHub contents API.
  defp list_namespace(namespace) do
    path = namespace |> String.split(".") |> Enum.join("/")

    url =
      "https://api.github.com/repos/bluesky-social/atproto/contents/lexicons/#{path}?ref=#{ref()}"

    case HTTP.get(url) do
      {:ok, %{status: 200, body: entries}} when is_list(entries) ->
        {:ok,
         entries
         |> Enum.map(& &1["name"])
         |> Enum.filter(&String.ends_with?(&1, ".json"))
         |> Enum.map(&String.trim_trailing(&1, ".json"))
         |> Enum.sort()}

      {:ok, %{status: status}} ->
        {:error, {:http, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_lexicon(nsid) do
    path = nsid |> String.split(".") |> Enum.join("/")

    case HTTP.get("#{raw()}/#{path}.json") do
      {:ok, %{status: 200, body: body}} when is_map(body) -> {:ok, body}
      {:ok, %{status: 200, body: body}} when is_binary(body) -> Jason.decode(body)
      {:ok, %{status: status}} -> {:error, {:http, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp check_call(nsid, kind, params, lexicon) do
    main = get_in(lexicon, ["defs", "main"]) || %{}

    expected_kind = Atom.to_string(kind)

    kind_drift =
      case main["type"] do
        nil -> ["#{nsid}: no `main` definition — the method is gone"]
        ^expected_kind -> []
        actual -> ["#{nsid}: is now a #{actual}, we call it as a #{expected_kind}"]
      end

    known = known_properties(main)

    param_drift =
      if known == :unknown do
        []
      else
        params
        |> Enum.reject(&(&1 in known))
        |> Enum.map(&"#{nsid}: sends `#{&1}`, which the lexicon no longer accepts")
      end

    kind_drift ++ param_drift
  end

  # A query takes parameters; a procedure takes a JSON body. Either way we want
  # the set of property names it will accept.
  defp known_properties(%{"parameters" => %{"properties" => properties}}),
    do: Map.keys(properties)

  defp known_properties(%{"input" => %{"schema" => %{"properties" => properties}}}),
    do: Map.keys(properties)

  # A method with neither (an input-less procedure, or a union schema we cannot
  # read this simply) tells us nothing about parameters; existence is the check.
  defp known_properties(_), do: :unknown
end
