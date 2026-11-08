defmodule Exosphere.ATProto.Spaces.SpaceMeta do
  @moduledoc """
  The space meta archive (proposal 0016, "Space meta archive"; atproto
  `35c0cf1`): an authority's host-side state for one space, moved between
  hosts when the authority's account migrates (`Spaces.Space.export_space_meta/4`
  → `import_space_meta/4`).

  It is a STAR archive (`Exosphere.ATProto.Star`) with the
  `atproto-space-meta` profile. The metadata is
  `{"$type": "atproto-space-meta", "ver": 1, "space": space_ref}`; the body
  has three sections, in this order, each in strict key-byte order:

  1. **Policy** — a single `policy` key, the space's policy object
     (`Spaces.Policy`).
  2. **Policy state** — anything else the policy keeps, keyed like record
     paths (`{nsid}/{rkey}`), e.g. memberspace's
     `com.atproto.memberspace.member/{did}` entries.
  3. **Writers** — one `writer/{did}` key per account in the writer set, with
     `repoRev`, `data` and `spaceRev` (what `listWriters` serves after
     migration). The repo revision was keyed `rev` until the
     `atproto-spaces-cleanup` branch (`4037310`) renamed it to match
     `listWriters`; an archive carrying `rev` is rejected as a malformed
     writer.

  `decode/1` rejects the archive on a parse error, a missing policy, a
  section out of place, a duplicate or out-of-order key, a non-map value, or
  a malformed writer. (Rejecting a policy or policy-state key the importing
  host does not implement is that host's call — `UnsupportedPolicy`.)
  Notification registrations, credential revocations and deleted-space
  tombstones are not carried over.
  """

  alias Exosphere.ATProto.CBOR, as: DagCbor
  alias Exosphere.ATProto.Identity.DID
  alias Exosphere.ATProto.{Star, TID}

  @star_type "atproto-space-meta"
  @version 1
  @limits [max_meta_length: 64 * 1024, max_key_length: 4 * 1024, max_value_length: 1024 * 1024]
  @writer_prefix "writer/"

  @type writer :: %{did: String.t(), repo_rev: String.t(), data: binary(), space_rev: String.t()}
  @type t :: %{
          space: String.t(),
          policy: map(),
          policy_state: [{String.t(), map()}],
          writers: [writer()]
        }

  @doc "Encode an archive; each section is put into key order."
  @spec encode(t()) :: binary()
  def encode(%{space: space, policy: %{} = policy} = archive) do
    state =
      archive
      |> Map.get(:policy_state, [])
      |> Enum.map(fn {key, value} -> {key, DagCbor.encode!(value)} end)
      |> Enum.sort_by(&elem(&1, 0))

    writers =
      archive
      |> Map.get(:writers, [])
      |> Enum.map(fn w ->
        value = %{
          "repoRev" => w.repo_rev,
          "data" => %CBOR.Tag{tag: :bytes, value: w.data},
          "spaceRev" => w.space_rev
        }

        {@writer_prefix <> w.did, DagCbor.encode!(value)}
      end)
      |> Enum.sort_by(&elem(&1, 0))

    meta = %{"$type" => @star_type, "ver" => @version, "space" => space}
    Star.encode(meta, [{"policy", DagCbor.encode!(policy)} | state] ++ writers)
  end

  @doc "Decode and validate an archive."
  @spec decode(binary()) :: {:ok, t()} | {:error, term()}
  def decode(star) when is_binary(star) do
    with {:ok, %{meta: meta, pairs: pairs}} <- Star.decode(star, @limits),
         {:ok, space} <- check_meta(meta),
         {:ok, sections} <- walk(pairs) do
      case sections.policy do
        nil ->
          {:error, :missing_policy}

        policy ->
          {:ok,
           %{
             space: space,
             policy: policy,
             policy_state: sections.state,
             writers: sections.writers
           }}
      end
    end
  end

  defp check_meta(%{"$type" => @star_type, "ver" => @version, "space" => space} = meta)
       when is_binary(space) and map_size(meta) == 3,
       do: {:ok, space}

  defp check_meta(%{"$type" => @star_type}), do: {:error, :invalid_space_meta}
  defp check_meta(_), do: {:error, :wrong_star_type}

  @sections [:policy, :state, :writers]

  defp walk(pairs) do
    initial = {:ok, %{policy: nil, state: [], writers: []}, nil, nil}

    result =
      Enum.reduce_while(pairs, initial, fn {key, value}, {:ok, acc, section, prev} ->
        key_section = section_of(key)

        with :ok <- check_section(section, key_section),
             prev = if(key_section == section, do: prev, else: nil),
             :ok <- check_order(prev, key),
             {:ok, map} <- decode_map(value),
             {:ok, acc} <- put(acc, key_section, key, map) do
          {:cont, {:ok, acc, key_section, key}}
        else
          error -> {:halt, error}
        end
      end)

    with {:ok, acc, _section, _prev} <- result do
      {:ok, %{acc | state: Enum.reverse(acc.state), writers: Enum.reverse(acc.writers)}}
    end
  end

  defp section_of("policy"), do: :policy
  defp section_of(@writer_prefix <> _), do: :writers
  defp section_of(_), do: :state

  defp check_section(nil, _), do: :ok

  defp check_section(current, next) do
    if index(next) < index(current), do: {:error, :section_out_of_order}, else: :ok
  end

  defp index(section), do: Enum.find_index(@sections, &(&1 == section))

  defp check_order(nil, _key), do: :ok
  defp check_order(prev, key) when key > prev, do: :ok
  defp check_order(_prev, key), do: {:error, {:duplicate_or_out_of_order_key, key}}

  defp put(acc, :policy, _key, map), do: {:ok, %{acc | policy: map}}
  defp put(acc, :state, key, map), do: {:ok, %{acc | state: [{key, map} | acc.state]}}

  defp put(acc, :writers, @writer_prefix <> did = key, map) do
    with true <- DID.valid?(did),
         %{"repoRev" => repo_rev, "data" => data, "spaceRev" => space_rev} when is_binary(data) <-
           map,
         true <- TID.valid?(repo_rev) and TID.valid?(space_rev) do
      writer = %{did: did, repo_rev: repo_rev, data: data, space_rev: space_rev}
      {:ok, %{acc | writers: [writer | acc.writers]}}
    else
      _ -> {:error, {:invalid_writer, key}}
    end
  end

  defp decode_map(bytes) do
    case CBOR.decode(bytes) do
      {:ok, raw, ""} ->
        case DagCbor.transform_links(raw) do
          %{} = map when not is_struct(map) -> {:ok, map}
          _ -> {:error, :value_not_a_map}
        end

      _ ->
        {:error, :invalid_cbor}
    end
  rescue
    _ -> {:error, :invalid_cbor}
  end
end
