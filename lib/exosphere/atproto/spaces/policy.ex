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
  | `managed/2` | `com.atproto.managedspace.policy` | whoever the managing app approves (`Spaces.Managedspace.check_access/4`) |

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

  ## Validation (November 12 alpha)

  Two baseline fields are checked beyond their lexicon types, as the
  reference host checks them on `createSpace` and `updateSpace`:

  - a managedspace `managingApp` must be a `did#serviceId` reference. A bare
    DID is refused (`{:error, :invalid_managing_app}`): the reference host
    resolves only the fragment form, so a space stored with a bare DID could
    never reach its managing app;
  - a memberspace's `allowedApps` entries are lexicon `uri`s (OAuth client
    IDs), `{:error, :invalid_allowed_apps}` otherwise.

  `decode/1` applies both, so a host normalizing a request body or a space
  meta archive gets the refusal, and `Spaces.Space.create_space/5` and
  `update_space/5` check locally before sending. The builders (`member/1`,
  `managed/2`) raise `ArgumentError` on the same inputs — a malformed
  literal is a programming error, not a runtime condition.
  """

  alias Exosphere.ATProto.Spaces.XRPC

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
  - `:allowed_apps` — OAuth client IDs, each a lexicon `uri`; when set, a
    credential is minted only for a listed app, checked against the
    *attested* `client_id`
  - `:publish_policy` — publish the policy as a `com.atproto.space.policy`
    record in the authority's repo in the space
  - `:publish_members` — publish the member list as
    `com.atproto.memberspace.member` records

  Raises `ArgumentError` when `:allowed_apps` is not a list of URIs.
  """
  @spec member(member_opts()) :: t()
  def member(opts \\ []) do
    allowed_apps = opts[:allowed_apps]

    unless is_nil(allowed_apps) or allowed_apps?(allowed_apps) do
      raise ArgumentError, "allowed_apps must be a list of URIs, got: #{inspect(allowed_apps)}"
    end

    %{"$type" => @member}
    |> put_opt("publicRead", opts[:public_read])
    |> put_opt("publicWrite", opts[:public_write])
    |> put_opt("allowedApps", allowed_apps)
    |> put_opt("publishPolicy", opts[:publish_policy])
    |> put_opt("publishMembers", opts[:publish_members])
  end

  @doc """
  `com.atproto.managedspace.policy`: each access decision is deferred to the
  managing app — a `did#serviceId` reference, e.g.
  `"did:web:app.example.com#forum"`, where the authority sends
  `com.atproto.managedspace.checkAccess` (`Spaces.Managedspace`). Option:
  `:publish_policy`.

  Raises `ArgumentError` for a bare DID or any other value that is not an
  atproto `did#serviceId` reference: since the November 12 alpha hosts refuse
  it on `createSpace` and `updateSpace`.
  """
  @spec managed(String.t(), keyword()) :: t()
  def managed(managing_app, opts \\ []) when is_binary(managing_app) do
    unless XRPC.did_service_ref?(managing_app) do
      raise ArgumentError,
            "managing_app must be a did#serviceId reference, got: #{inspect(managing_app)}"
    end

    %{"$type" => @managed, "managingApp" => managing_app}
    |> put_opt("publishPolicy", opts[:publish_policy])
  end

  @doc """
  Decode a policy object (from `getSpace`, a published
  `com.atproto.space.policy` record, a `createSpace`/`updateSpace` request
  body, or a space meta archive) into a tagged tuple with snake_case keys and
  the lexicon defaults filled in. Any other `$type` is `{:unknown, policy}`.

  Refusals: `{:error, :invalid_managing_app}` for a managedspace whose
  `managingApp` is missing or not a `did#serviceId` reference (a bare DID
  included), `{:error, :invalid_allowed_apps}` for a memberspace whose
  `allowedApps` is not a list of URIs, and `{:error, :invalid_policy}` for a
  value that is not a policy object at all.
  """
  @spec decode(term()) ::
          {:ok, decoded()}
          | {:error, :invalid_policy | :invalid_managing_app | :invalid_allowed_apps}
  def decode(%{"$type" => @personal}), do: {:ok, {:personal, %{}}}

  def decode(%{"$type" => @member} = policy) do
    allowed_apps = Map.get(policy, "allowedApps")

    if is_nil(allowed_apps) or allowed_apps?(allowed_apps) do
      {:ok,
       {:member,
        %{
          public_read: Map.get(policy, "publicRead", false),
          public_write: Map.get(policy, "publicWrite", false),
          allowed_apps: allowed_apps,
          publish_policy: Map.get(policy, "publishPolicy", false),
          publish_members: Map.get(policy, "publishMembers", false)
        }}}
    else
      {:error, :invalid_allowed_apps}
    end
  end

  def decode(%{"$type" => @managed} = policy) do
    app = Map.get(policy, "managingApp")

    if XRPC.did_service_ref?(app) do
      {:ok,
       {:managed, %{managing_app: app, publish_policy: Map.get(policy, "publishPolicy", false)}}}
    else
      {:error, :invalid_managing_app}
    end
  end

  def decode(%{"$type" => type} = policy) when is_binary(type), do: {:ok, {:unknown, policy}}
  def decode(_), do: {:error, :invalid_policy}

  @doc """
  Check a policy object the way `decode/1` does, without decoding it: `:ok`
  for a valid baseline policy or any other `$type`, the `decode/1` refusal
  otherwise.
  """
  @spec validate(term()) ::
          :ok | {:error, :invalid_policy | :invalid_managing_app | :invalid_allowed_apps}
  def validate(policy) do
    with {:ok, _} <- decode(policy), do: :ok
  end

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

  defp allowed_apps?(apps), do: is_list(apps) and Enum.all?(apps, &XRPC.uri?/1)

  defp put_opt(map, _key, nil), do: map
  defp put_opt(map, key, value), do: Map.put(map, key, value)
end
