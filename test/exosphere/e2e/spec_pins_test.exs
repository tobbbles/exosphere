defmodule Exosphere.SpecPinsTest do
  @moduledoc """
  Re-verify the Spaces spec pins against the alpha lexicons.

  The `spaces/alpha` branch pins its cross-checks to a point in a moving alpha
  spec, and "re-verify the pins before promoting anything" has been a manual
  checklist item. This makes it runnable: it fetches the space lexicons from
  the atproto repository and checks, mechanically, that every method this
  library calls still exists and that every parameter it sends is still a
  property that method accepts.

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

  @moduletag :external
  @moduletag timeout: 120_000

  # What `spaces/alpha` follows: atproto branch `atproto-spaces-cleanup` at
  # 4037310, which carries `atproto-spaces-lexicon-review` (7089c42). Its
  # lexicons are `permissioned-data` 98ef3a6's plus that branch's changes
  # (`permissioned-data` has not touched lexicons since the fork point).
  @pinned_commit "4037310976201ee057f1b06aeef04a3cdc080258"
  @pinned_branch "atproto-spaces-cleanup"

  # Every space method this library calls, with the parameters it sends. Kept
  # here by hand rather than derived from the source: the point is to state
  # what we believe the wire contract to be, and have the lexicon disagree.
  @calls [
    {"com.atproto.space.getDelegationToken", :query, ["space"]},
    {"com.atproto.space.getSpaceCredential", :procedure,
     ["space", "credentialKey", "delegationToken", "clientAttestation"]},
    {"com.atproto.space.listWriters", :query, ["space", "limit", "cursor"]},
    {"com.atproto.space.getLatestCommit", :query, ["space", "repo"]},
    {"com.atproto.space.listRepoOps", :query,
     ["space", "repo", "since", "cursor", "limit", "excludeValues"]},
    {"com.atproto.space.listRecords", :query,
     ["space", "repo", "collection", "cursor", "limit", "excludeValues"]},
    {"com.atproto.space.getRecord", :query, ["space", "repo", "collection", "rkey"]},
    {"com.atproto.space.getRepo", :query, ["space", "repo"]},
    {"com.atproto.space.registerNotify", :procedure, ["space", "service"]},
    {"com.atproto.space.unregisterNotify", :procedure, ["space", "service"]},
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

  # Methods whose bodies this library decodes (it receives them, it does not
  # call them), with the fields it reads.
  @received [
    {"com.atproto.space.notifyRepoUpdate", ["space", "repo", "repoRev", "data"]},
    {"com.atproto.space.notifySpaceStatus", ["space", "status"]},
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

  test "the listWriters fields this library reads are still the ones the lexicon returns" do
    # The parameter check above only sees what we *send*. `Sync.list_writers/4`
    # also *reads* named fields off each entry, and a rename there is silent on
    # our side — the old name simply decodes to nil. It has happened three
    # times (`rev` → `repoRev` + `spaceRev`, atproto 357c4cee9; `hash` →
    # `data`, 5791385; `did` → `repo`, atproto-spaces-lexicon-review), so it
    # is checked.
    assert {:ok, lexicon} = fetch_lexicon("com.atproto.space.listWriters")
    repo = get_in(lexicon, ["defs", "repo"])

    for field <- ["repo", "repoRev", "spaceRev", "data"] do
      assert field in repo["required"],
             "com.atproto.space.listWriters#repo no longer requires `#{field}`, which list_writers/4 reads"
    end

    assert repo["properties"]["data"]["type"] == "bytes"
  end

  test "the notification bodies this library decodes still require what it reads" do
    for {nsid, fields} <- @received do
      assert {:ok, lexicon} = fetch_lexicon(nsid)
      required = get_in(lexicon, ["defs", "main", "input", "schema", "required"]) || []

      for field <- fields do
        assert field in required, "#{nsid} no longer requires `#{field}`, which we decode"
      end
    end

    assert {:ok, status} = fetch_lexicon("com.atproto.space.notifySpaceStatus")

    assert "deleted" in get_in(status, [
             "defs",
             "main",
             "input",
             "schema",
             "properties",
             "status",
             "knownValues"
           ])
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

  test "unregisterNotify is service-authed, registerNotify credential-authed" do
    # Auth lives in prose, not schema: the descriptions are what upstream
    # publishes about it.
    assert {:ok, unregister} = fetch_lexicon("com.atproto.space.unregisterNotify")
    assert get_in(unregister, ["defs", "main", "description"]) =~ "service auth"

    assert {:ok, register} = fetch_lexicon("com.atproto.space.registerNotify")
    assert get_in(register, ["defs", "main", "description"]) =~ "space credential"
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

    assert Enum.sort(refs) == Enum.sort(Exosphere.ATProto.Spaces.Policy.baseline_types())
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
