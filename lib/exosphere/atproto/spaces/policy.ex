defmodule Exosphere.ATProto.Spaces.Policy do
  @moduledoc """
  The space `policy` union (proposal 0016, "Space policy" and "Baseline
  policies"; atproto `7992095`): the single object that configures a space
  under a policy, identified by its `$type`. `Spaces.Space.create_space/5` and
  `update_space/5` take one; `get_space/4` returns one.

  Every PDS supports the three baseline policies:

  | Policy | `$type` | Who reads |
  |---|---|---|
  | `personal/0` | `com.atproto.personalspace.policy` | only the authority |
  | `member/1` | `com.atproto.memberspace.policy` | members on the PDS's list (`Spaces.Memberspace`), or anyone with `public_read: true` |
  | `managed/2` | `com.atproto.managedspace.policy` | whoever the managing app approves (`Spaces.Managedspace.check_user_access/6`) |

  Until atproto `7992095` (2026-10-29) a simplespace had separate
  `readPolicy`/`writePolicy`/`appAccess` axes; they are folded into these
  policies (app gating is memberspace's `allowed_apps`, a managing app decides
  reads and writes alike).

      Policy.member(public_read: true, allowed_apps: ["https://app.example.com/client-metadata.json"])
      #=> %{"$type" => "com.atproto.memberspace.policy", "publicRead" => true,
      #     "allowedApps" => ["https://app.example.com/client-metadata.json"]}

  A policy the host does not implement is refused with `UnsupportedPolicy`;
  `decode/1` keeps any other `$type` as `{:unknown, map}` rather than
  failing, since policies beyond the baseline are legitimate.
  """

  @personal "com.atproto.personalspace.policy"
  @member "com.atproto.memberspace.policy"
  @managed "com.atproto.managedspace.policy"

  @typedoc "A policy object in its wire (lexicon) shape."
  @type t :: %{required(String.t()) => term()}

  @type member_opts :: [
          public_read: boolean(),
          public_write: boolean(),
          allowed_apps: [String.t()] | nil,
          publish_policy: boolean(),
          publish_members: boolean()
        ]

  @type decoded ::
          {:personal, %{}}
          | {:member, map()}
          | {:managed, map()}
          | {:unknown, t()}

  @doc "The `$type` NSIDs of the baseline policies."
  @spec baseline_types() :: [String.t()]
  def baseline_types, do: [@personal, @member, @managed]

  @doc """
  `com.atproto.personalspace.policy`: only the authority's own account reads,
  and no other writers are tracked. No configuration.
  """
  @spec personal() :: t()
  def personal, do: %{"$type" => @personal}

  @doc """
  `com.atproto.memberspace.policy`: access via a member list the PDS keeps.

  Options (all default to the lexicon default, and are omitted when unset):

  - `:public_read` — issue a credential to anyone, no delegation token needed
  - `:public_write` — track and forward any user's writes
  - `:allowed_apps` — OAuth client IDs; when set, a credential is minted only
    for a listed app, checked against the *attested* `client_id`
  - `:publish_policy` — publish the policy as a `com.atproto.space.policy`
    record in the authority's repo in the space
  - `:publish_members` — publish the member list as
    `com.atproto.memberspace.member` records
  """
  @spec member(member_opts()) :: t()
  def member(opts \\ []) do
    %{"$type" => @member}
    |> put_opt("publicRead", opts[:public_read])
    |> put_opt("publicWrite", opts[:public_write])
    |> put_opt("allowedApps", opts[:allowed_apps])
    |> put_opt("publishPolicy", opts[:publish_policy])
    |> put_opt("publishMembers", opts[:publish_members])
  end

  @doc """
  `com.atproto.managedspace.policy`: each access decision is deferred to the
  managing app — a service identifier (a DID with an optional fragment, e.g.
  `"did:web:app.example.com#forum"`). Option: `:publish_policy`.
  """
  @spec managed(String.t(), keyword()) :: t()
  def managed(managing_app, opts \\ []) when is_binary(managing_app) do
    %{"$type" => @managed, "managingApp" => managing_app}
    |> put_opt("publishPolicy", opts[:publish_policy])
  end

  @doc """
  Decode a policy object (from `getSpace`, a published
  `com.atproto.space.policy` record, or a space meta archive) into a tagged
  tuple with snake_case keys and the lexicon defaults filled in. Any other
  `$type` is `{:unknown, policy}`; a value that is not a policy object at all
  is `{:error, :invalid_policy}`.
  """
  @spec decode(term()) :: {:ok, decoded()} | {:error, :invalid_policy}
  def decode(%{"$type" => @personal}), do: {:ok, {:personal, %{}}}

  def decode(%{"$type" => @member} = policy) do
    {:ok,
     {:member,
      %{
        public_read: Map.get(policy, "publicRead", false),
        public_write: Map.get(policy, "publicWrite", false),
        allowed_apps: Map.get(policy, "allowedApps"),
        publish_policy: Map.get(policy, "publishPolicy", false),
        publish_members: Map.get(policy, "publishMembers", false)
      }}}
  end

  def decode(%{"$type" => @managed, "managingApp" => app} = policy) when is_binary(app) do
    {:ok,
     {:managed, %{managing_app: app, publish_policy: Map.get(policy, "publishPolicy", false)}}}
  end

  def decode(%{"$type" => @managed}), do: {:error, :invalid_policy}
  def decode(%{"$type" => type} = policy) when is_binary(type), do: {:ok, {:unknown, policy}}
  def decode(_), do: {:error, :invalid_policy}

  @doc """
  The `com.atproto.space.policy` record (key `self`) a PDS publishes in the
  authority's own repo when the policy sets `publish_policy` (proposal 0016,
  "Publishing to readers"; atproto `7992095`). Only authoritative in the
  authority's repo — any member can write a record of this type to their own.
  """
  @spec record(t()) :: map()
  def record(%{"$type" => _} = policy),
    do: %{"$type" => "com.atproto.space.policy", "policy" => policy}

  @doc "The record key of the published policy record."
  @spec record_key() :: String.t()
  def record_key, do: "self"

  defp put_opt(map, _key, nil), do: map
  defp put_opt(map, key, value), do: Map.put(map, key, value)
end
