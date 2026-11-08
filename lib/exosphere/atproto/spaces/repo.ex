defmodule Exosphere.ATProto.Spaces.Repo do
  @moduledoc """
  Permissioned repo serialization and verification: the `atproto-space-repo`
  STAR profile (proposal 0016, "Repo serialization"; atproto `bf02818`,
  `13994f1`, `bd58bd8`).

  A space repo is served by `getRepo` (and imported by `importRepo`) as a
  STAR archive (`Exosphere.ATProto.Star`):

  - the metadata is a DRISL map with `$type: "atproto-space-repo"` and every
    field of the repo's commit (`ver`, `repo`, `space`, `rev`, `data`);
  - each pair is a record path `"{collection}/{rkey}"` (UTF-8) and the
    record's DRISL encoding, in **strict lexicographic order of the key
    bytes**, no duplicates; an empty repo has no pairs.

  The commit's MAC travels in the response's `Atproto-Space-Mac` header, not
  in the archive. `verify/4` runs the consumer pipeline the proposal lays
  out, rejecting the whole archive on any failure: validate the metadata
  (type, version, and that `repo`/`space` are the ones requested), verify
  the commit MAC, then fold every record's
  `{collection}/{rkey}/{record_cid}` into a fresh set hash and require its
  digest to equal the commit's `data` — only that match shows the repo was
  received complete. `read/1` does the same without a MAC, for a host
  importing an account's own repo.

  Archive limits (the profile's operational caps): metadata 64 KiB, keys
  4 KiB, values 1 MiB.

  Until atproto `bf02818` the repo was a two-root CAR (signed commit block,
  canonical index block, record blocks) with an index-only variant
  (`excludeValues`); both are gone, as is that variant.
  """

  alias Exosphere.ATProto.CBOR, as: DagCbor
  alias Exosphere.ATProto.CID
  alias Exosphere.ATProto.{NSID, RecordKey, Star}
  alias Exosphere.ATProto.Spaces.{Commit, Lthash}

  @star_type "atproto-space-repo"
  @limits [max_meta_length: 64 * 1024, max_key_length: 4 * 1024, max_value_length: 1024 * 1024]

  @type verified_record :: %{
          required(:collection) => String.t(),
          required(:rkey) => String.t(),
          required(:cid) => CID.t(),
          required(:record) => map()
        }

  @type verified :: %{
          required(:commit) => Commit.t(),
          required(:records) => [verified_record()],
          required(:lthash) => Lthash.t(),
          required(:rev) => String.t()
        }

  @doc "The STAR profile name (`$type`)."
  @spec star_type() :: String.t()
  def star_type, do: @star_type

  @doc "The profile's archive limits, as `Star.decode/2` options."
  @spec limits() :: Star.limits()
  def limits, do: @limits

  @doc """
  Serialize a repo as an `atproto-space-repo` STAR archive.

  `records` is a list of `{collection, rkey, record_map}`; they are written in
  strict path-byte order whatever the input order. Duplicate paths raise.
  Blobs are not included.
  """
  @spec serialize(Commit.t(), [{String.t(), String.t(), map()}]) :: binary()
  def serialize(%{} = commit, records) when is_list(records) do
    pairs =
      records
      |> Enum.map(fn {collection, rkey, record} ->
        {record_path(collection, rkey), DagCbor.encode!(record)}
      end)
      |> Enum.sort_by(&elem(&1, 0))

    paths = Enum.map(pairs, &elem(&1, 0))

    if length(Enum.uniq(paths)) != length(paths) do
      raise ArgumentError, "duplicate record path in space repo"
    end

    Star.encode(Map.put(Commit.to_dag_cbor(commit), "$type", @star_type), pairs)
  end

  @doc """
  Verify a repo archive served for `ctx` (`%{space:, repo:}`, the request)
  against the commit MAC from its response header, end to end. On success
  the returned set hash is the authenticated running hash to continue
  syncing from.
  """
  @spec verify(binary(), Commit.ctx(), binary(), binary()) :: {:ok, verified()} | {:error, term()}
  def verify(star, %{space: _, repo: _} = ctx, shared_secret, mac) when is_binary(star) do
    with {:ok, %{meta: meta, pairs: pairs}} <- Star.decode(star, @limits),
         {:ok, commit} <- commit_from_meta(meta),
         :ok <- Commit.verify(commit, ctx, shared_secret, mac) do
      verify_records(commit, pairs)
    end
  end

  @doc """
  Read a repo archive *without* authenticating its commit: the records are
  still checked against the commit's `data`, but nothing vouches for the
  commit itself. For a repo host importing an account's own repo
  (`importRepo`), which carries no MAC.
  """
  @spec read(binary()) :: {:ok, verified()} | {:error, term()}
  def read(star) when is_binary(star) do
    with {:ok, %{meta: meta, pairs: pairs}} <- Star.decode(star, @limits),
         {:ok, commit} <- commit_from_meta(meta) do
      verify_records(commit, pairs)
    end
  end

  defp commit_from_meta(%{"$type" => @star_type} = meta) do
    commit = Map.delete(meta, "$type")

    cond do
      commit["ver"] != Commit.version() -> {:error, {:unsupported_commit_version, commit["ver"]}}
      Commit.well_formed?(commit) -> {:ok, commit}
      true -> {:error, :invalid_commit}
    end
  end

  defp commit_from_meta(_), do: {:error, :wrong_star_type}

  defp verify_records(commit, pairs) do
    result =
      Enum.reduce_while(pairs, {:ok, nil, Lthash.new(), []}, fn {key, value},
                                                                {:ok, prev, hash, acc} ->
        with :ok <- check_order(prev, key),
             {:ok, collection, rkey} <- parse_record_path(key),
             {:ok, record} <- decode_record(value) do
          cid = %CID{version: 1, codec: :dag_cbor, hash: :crypto.hash(:sha256, value)}
          hash = Commit.add_record(hash, collection, rkey, CID.encode(cid))
          entry = %{collection: collection, rkey: rkey, cid: cid, record: record}
          {:cont, {:ok, key, hash, [entry | acc]}}
        else
          error -> {:halt, error}
        end
      end)

    with {:ok, _last, lthash, acc} <- result do
      if Commit.matches?(lthash, commit) do
        {:ok, %{commit: commit, records: Enum.reverse(acc), lthash: lthash, rev: commit["rev"]}}
      else
        {:error, :records_do_not_match_commit}
      end
    end
  end

  # Strict lexicographic byte order; Erlang compares binaries bytewise, a
  # prefix sorting before any longer key it starts.
  defp check_order(nil, _key), do: :ok
  defp check_order(prev, key) when key > prev, do: :ok
  defp check_order(_prev, key), do: {:error, {:records_out_of_order, key}}

  defp parse_record_path(path) do
    with true <- String.valid?(path),
         [collection, rkey] <- String.split(path, "/"),
         true <- NSID.valid?(collection),
         true <- RecordKey.valid?(rkey) do
      {:ok, collection, rkey}
    else
      _ -> {:error, {:invalid_record_path, path}}
    end
  end

  # The whole value must be one CBOR item (no trailing bytes) and a map.
  defp decode_record(bytes) do
    case CBOR.decode(bytes) do
      {:ok, raw, ""} ->
        case DagCbor.transform_links(raw) do
          %{} = record when not is_struct(record) -> {:ok, record}
          _ -> {:error, :invalid_record}
        end

      _ ->
        {:error, :invalid_record}
    end
  rescue
    _ -> {:error, :invalid_record}
  end

  defp record_path(collection, rkey), do: collection <> "/" <> rkey
end
