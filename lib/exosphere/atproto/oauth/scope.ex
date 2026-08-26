defmodule Exosphere.ATProto.OAuth.Scope do
  @moduledoc """
  The `space:` OAuth scope grammar of atproto permissioned data (proposal
  0016): parsing, canonical formatting, and matching for the scopes an
  ATProto OAuth client requests and a resource server enforces. Scope
  *strings* travel in client metadata and token responses
  (`Exosphere.ATProto.OAuth.ClientMetadata`); this module gives them
  structure and semantics.

  A space scope grants access to a class of spaces and (for writes) the
  record collections within them:

      space:{spaceType}[?authority=…&skey=…&collection=…&action=…&manage=…]

  - `spaceType` (required): an NSID naming the space type — the OAuth consent
    boundary ("access to your AtmoBoards forums") — or `*` for any type
  - `authority`: a DID, `self` (default — the granting user's own spaces), or
    `*`
  - `skey`: a space key (record-key syntax) or `*` (default)
  - `collection` (repeatable): the write-target collections; defaults to the
    space type's *declared* collections, resolved dynamically at token
    issuance (see `with_default_collections/2`) — not frozen at consent time;
    `*` widens to any
  - `action` (repeatable): `read_self`, `read`, `create`, `update`, `delete`.
    Default is the full record action list. `read` is all-or-nothing across
    collections and implies `read_self`
  - `manage` (repeatable): space administration (`create`/`update`/`delete`,
    mapping to simplespace operations under `manage=update`); no default

  An empty `collection` list means *no write targets* — not "all collections".
  Bundling into OAuth permission sets requires a concrete spaceType.
  """

  alias Exosphere.ATProto.Identity.DID
  alias Exosphere.ATProto.{NSID, RecordKey}

  @prefix "space"

  @action_order [:read_self, :read, :create, :update, :delete]
  @manage_order [:create, :update, :delete]
  @default_actions [:read, :create, :update, :delete]

  @known_params ~w(authority skey collection action manage)

  @enforce_keys [:type]
  defstruct [:type, :authority, :skey, :collections, :actions, :manage]

  @type type_param :: :any | String.t()
  @type authority_param :: :any | :self | String.t()
  @type skey_param :: :any | String.t()
  @type collection_param :: :any | String.t()
  @type action :: :read_self | :read | :create | :update | :delete
  @type manage_op :: :create | :update | :delete

  @type t :: %__MODULE__{
          type: type_param(),
          authority: authority_param(),
          skey: skey_param(),
          collections: [collection_param()],
          actions: [action()],
          manage: [manage_op()]
        }

  @doc """
  Parse a `space:` scope string.

  Unknown parameters, malformed values, and a positional type combined with a
  named `type` parameter are rejected; single-valued parameters may not
  repeat.
  """
  @spec parse(String.t()) :: {:ok, t()} | {:error, :invalid_scope}
  def parse("space:" <> rest) do
    {type_part, params} = split(rest)

    with {:ok, type} <- parse_type(type_part),
         {:ok, params} <- parse_params(params),
         :ok <- reject_named_type(params),
         {:ok, authority} <- single(params, "authority", &parse_authority/1),
         {:ok, skey} <- single(params, "skey", &parse_skey/1),
         {:ok, collections} <- repeated(params, "collection", &parse_collection/1),
         {:ok, actions} <- repeated(params, "action", &parse_action/1),
         {:ok, manage} <- repeated(params, "manage", &parse_manage/1) do
      {:ok,
       %__MODULE__{
         type: type,
         authority: authority || :self,
         skey: skey || :any,
         collections: collections || [],
         actions: actions || @default_actions,
         manage: manage || []
       }}
    end
  end

  def parse(_), do: {:error, :invalid_scope}

  @doc """
  Format a scope canonically: defaults omitted, repeatable params deduplicated
  in canonical order (`collections` sorted, or collapsed to `*`), params in
  grammar order.
  """
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{} = scope) do
    params = [
      {"authority", scope.authority == :self, [scope.authority]},
      {"skey", scope.skey == :any, [scope.skey]},
      {"collection", scope.collections == [], normalize_collections(scope.collections)},
      {"action", actions_default?(scope.actions), canonical(scope.actions, @action_order)},
      {"manage", scope.manage == [], canonical(scope.manage, @manage_order)}
    ]

    pairs = for {key, default?, values} <- params, not default?, v <- values, do: {key, param(v)}

    case pairs do
      [] -> @prefix <> ":" <> param(scope.type)
      _ -> @prefix <> ":" <> param(scope.type) <> "?" <> encode_query(pairs)
    end
  end

  # Scope components keep URI-reserved but scope-legal characters unencoded
  # (":", "/", "+", ",", "@", "%" on top of the unreserved set), matching the
  # reference normalization — DIDs stay readable instead of %3A soup.
  @unreserved_bytes Enum.to_list(?a..?z) ++
                      Enum.to_list(?A..?Z) ++
                      Enum.to_list(?0..?9) ++
                      Enum.map(~c"-._~:/+,@%*", & &1)

  defp encode_query(pairs) do
    Enum.map_join(pairs, "&", fn {k, v} ->
      encode_param(k) <> "=" <> encode_param(v)
    end)
  end

  defp encode_param(value) do
    for <<byte <- value>>, into: "" do
      if byte in @unreserved_bytes do
        <<byte>>
      else
        "%" <> Base.encode16(<<byte>>, case: :upper)
      end
    end
  end

  @doc """
  Whether the scope authorizes a concrete target — a manage operation or a
  record action in a concrete collection:

      matches?(scope, %{type: t, authority: did, skey: k, manage: :update})
      matches?(scope, %{type: t, authority: did, skey: k, action: :read})

  Reads are collection-independent; `read` implies `read_self`; writes need
  the action *and* a covering collection. An unresolved `self` authority
  matches nothing (targets are concrete DIDs) — resolve first with
  `with_resolved_authority/2`.
  """
  @spec matches?(t(), map()) :: boolean()
  def matches?(%__MODULE__{} = scope, %{} = target) do
    covers?(scope.type, target.type) and covers?(scope.authority, target.authority) and
      covers?(scope.skey, target.skey) and matches_permission?(scope, target)
  end

  @doc """
  Materialize a space type's declared collections into a bare `space:<type>`
  grant. Called at token-issuance time (the matcher itself is context-free); a
  grant that already names collections, or an empty declaration, passes
  through unchanged.
  """
  @spec with_default_collections(t(), [String.t()]) :: t()
  def with_default_collections(%__MODULE__{collections: []} = scope, [_ | _] = declared),
    do: %__MODULE__{scope | collections: Enum.sort(Enum.uniq(declared))}

  def with_default_collections(scope, _), do: scope

  @doc """
  Resolve an `authority` of `self` to the granting user's DID, at token
  issuance.
  """
  @spec with_resolved_authority(t(), DID.did()) :: t()
  def with_resolved_authority(%__MODULE__{authority: :self} = scope, did),
    do: %__MODULE__{scope | authority: did}

  def with_resolved_authority(scope, _), do: scope

  # -- parsing -----------------------------------------------------------------

  defp split(rest) do
    case String.split(rest, "?", parts: 2) do
      [type] -> {type, %{}}
      [type, ""] -> {type, %{}}
      [type, query] -> {type, parse_query(query)}
    end
  end

  # Every key maps to the list of its (percent-decoded) values, repeats
  # preserved — matching the reference's URLSearchParams / decodeURIComponent
  # handling, so `space:t?authority=did%3Aplc%3Aabc` parses.
  defp parse_query(query) do
    query
    |> String.split("&", trim: true)
    |> Enum.map(fn pair ->
      case String.split(pair, "=", parts: 2) do
        [k, v] -> {percent_decode(k), percent_decode(v)}
        [k] -> {percent_decode(k), ""}
      end
    end)
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
  end

  # RFC 3986 percent-decoding (not form decoding: '+' stays '+').
  defp percent_decode(value) do
    case String.split(value, "%") do
      [_single] ->
        value

      [head | encoded] ->
        decode_parts(encoded, head)
    end
  catch
    :throw, :bad_percent -> value
  end

  defp decode_parts([h | t], acc) do
    case h do
      <<hex::binary-size(2), rest::binary>> when byte_size(hex) == 2 ->
        case Integer.parse(hex, 16) do
          {byte, ""} when byte in 0..255 ->
            decode_parts(t, <<acc::binary, byte, rest::binary>>)

          _ ->
            throw(:bad_percent)
        end

      _ ->
        throw(:bad_percent)
    end
  end

  defp decode_parts([], acc), do: acc

  defp parse_params(params) do
    if Enum.all?(Map.keys(params), &(&1 in @known_params)) do
      {:ok, params}
    else
      {:error, :invalid_scope}
    end
  end

  defp parse_type("*"), do: {:ok, :any}

  defp parse_type(type) do
    if NSID.valid?(percent_decode(type)),
      do: {:ok, percent_decode(type)},
      else: {:error, :invalid_scope}
  end

  defp reject_named_type(%{"type" => _}), do: {:error, :invalid_scope}
  defp reject_named_type(_), do: :ok

  defp single(params, key, parser) do
    case Map.fetch(params, key) do
      :error -> {:ok, nil}
      {:ok, [value]} -> parser.(value)
      {:ok, _} -> {:error, :invalid_scope}
    end
  end

  defp repeated(params, key, parser) do
    case Map.fetch(params, key) do
      :error -> {:ok, nil}
      {:ok, values} -> parser.(values)
    end
  end

  defp parse_authority("*"), do: {:ok, :any}
  defp parse_authority("self"), do: {:ok, :self}

  defp parse_authority(did) do
    if DID.valid?(did), do: {:ok, did}, else: {:error, :invalid_scope}
  end

  defp parse_skey("*"), do: {:ok, :any}

  defp parse_skey(skey) do
    if RecordKey.valid?(skey), do: {:ok, skey}, else: {:error, :invalid_scope}
  end

  defp parse_collection(values) do
    values
    |> Enum.reduce_while({:ok, []}, fn
      "*", {:ok, acc} ->
        {:cont, {:ok, [:any | acc]}}

      "*", _ ->
        {:halt, {:error, :invalid_scope}}

      ns, {:ok, acc} ->
        if NSID.valid?(ns),
          do: {:cont, {:ok, [ns | acc]}},
          else: {:halt, {:error, :invalid_scope}}
    end)
    |> case do
      {:ok, cols} -> {:ok, normalize_collections(cols)}
      error -> error
    end
  end

  defp parse_action(values), do: parse_enum(values, @action_order)

  defp parse_manage(values), do: parse_enum(values, @manage_order)

  defp parse_enum(values, order) do
    values
    |> Enum.reduce_while({:ok, []}, fn value, {:ok, acc} ->
      case Enum.find(order, &(Atom.to_string(&1) == value)) do
        nil -> {:halt, {:error, :invalid_scope}}
        atom -> {:cont, {:ok, [atom | acc]}}
      end
    end)
    |> case do
      {:ok, atoms} -> {:ok, Enum.filter(order, &(&1 in atoms))}
      error -> error
    end
  end

  defp normalize_collections(cols) do
    if :any in cols, do: [:any], else: cols |> Enum.uniq() |> Enum.sort()
  end

  # -- formatting ----------------------------------------------------------------

  defp param(:any), do: "*"

  defp param(:self), do: "self"

  defp param(value) when is_atom(value), do: Atom.to_string(value)

  defp param(value) when is_binary(value), do: value

  defp canonical(values, order), do: Enum.filter(order, &(&1 in values))

  defp actions_default?(actions),
    do: canonical(actions, @action_order) == @default_actions

  # -- matching --------------------------------------------------------------------

  defp matches_permission?(scope, %{manage: op}) when is_atom(op), do: op in scope.manage
  defp matches_permission?(scope, %{action: :read}), do: :read in scope.actions

  defp matches_permission?(scope, %{action: :read_self}),
    do: :read in scope.actions or :read_self in scope.actions

  defp matches_permission?(scope, %{action: action, collection: collection})
       when is_atom(action) and is_binary(collection),
       do: action in scope.actions and allows_collection?(scope, collection)

  defp matches_permission?(_, _), do: false

  defp covers?(:any, _), do: true
  defp covers?(granted, target), do: granted == target

  defp allows_collection?(%__MODULE__{collections: collections}, collection),
    do: :any in collections or collection in collections
end
