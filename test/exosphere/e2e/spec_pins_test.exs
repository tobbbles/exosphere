defmodule Exosphere.SpecPinsTest do
  @moduledoc """
  Re-verify the Spaces spec pins against the current alpha lexicons.

  The `spaces/alpha` branch pins its cross-checks to a point in a moving alpha
  spec, and "re-verify the pins before promoting anything" has been a manual
  checklist item. This makes it runnable: it fetches the space lexicons from
  the atproto implementation branch and checks, mechanically, that every method
  this library calls still exists and that every parameter it sends is still a
  property that method accepts.

  Excluded from the default run (it needs the network). Opt in with:

      mix test --only external

  A failure here is information, not a bug: the alpha moved, and the client
  needs to move with it. Read the diff before changing code.
  """

  use ExUnit.Case, async: true

  alias Exosphere.ATProto.HTTP

  @moduletag :external
  @moduletag timeout: 120_000

  # The atproto implementation branch carrying the Spaces alpha (PR #5187).
  # The branch, not a SHA: the point of this suite is to see the current state.
  @branch "permissioned-data-alpha"
  @raw "https://raw.githubusercontent.com/bluesky-social/atproto/#{@branch}/lexicons"

  # What `spaces/alpha` pinned against, recorded so drift is legible.
  @pinned_commit "5fbc9a0"

  # Every space method this library calls, with the parameters it sends. Kept
  # here by hand rather than derived from the source: the point is to state
  # what we believe the wire contract to be, and have the lexicon disagree.
  @calls [
    {"com.atproto.space.getDelegationToken", :query, ["space"]},
    {"com.atproto.space.getSpaceCredential", :procedure, ["space", "clientAttestation"]},
    {"com.atproto.space.listRepos", :query, ["space", "limit", "cursor"]},
    {"com.atproto.space.getLatestCommit", :query, ["space", "repo"]},
    {"com.atproto.space.listRepoOps", :query,
     ["space", "repo", "since", "cursor", "limit", "excludeValues"]},
    {"com.atproto.space.listRecords", :query, ["space", "repo", "collection", "cursor", "limit"]},
    {"com.atproto.space.getRecord", :query, ["space", "repo", "collection", "rkey"]},
    {"com.atproto.space.getRepo", :query, ["space", "repo"]},
    {"com.atproto.space.registerNotify", :procedure, ["space", "service"]},
    {"com.atproto.space.unregisterNotify", :procedure, ["space", "service"]},
    {"com.atproto.space.createRecord", :procedure, ["space", "collection", "rkey", "record"]},
    {"com.atproto.space.putRecord", :procedure, ["space", "collection", "rkey", "record"]},
    {"com.atproto.space.deleteRecord", :procedure, ["space", "collection", "rkey"]},
    {"com.atproto.space.applyWrites", :procedure, ["space", "writes"]},
    {"com.atproto.simplespace.createSpace", :procedure, ["type", "skey", "policy", "appAccess"]},
    {"com.atproto.simplespace.updateSpace", :procedure, ["space", "policy", "appAccess"]},
    {"com.atproto.simplespace.deleteSpace", :procedure, ["space"]},
    {"com.atproto.simplespace.getSpace", :query, ["space"]},
    {"com.atproto.simplespace.addMember", :procedure, ["space", "did"]},
    {"com.atproto.simplespace.removeMember", :procedure, ["space", "did"]},
    {"com.atproto.simplespace.listMembers", :query, ["space", "limit", "cursor"]},
    {"com.atproto.simplespace.checkUserAccess", :query, ["space", "user", "clientId"]}
  ]

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

           Pinned at atproto #{@pinned_commit}; checked against branch #{@branch}.

           #{Enum.map_join(drift, "\n", &("  - " <> &1))}
           """
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

    case HTTP.get("#{@raw}/#{path}.json") do
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
