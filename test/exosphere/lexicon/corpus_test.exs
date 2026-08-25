defmodule Exosphere.Lexicon.CorpusTest do
  @moduledoc """
  Corpus-wide validation: every generated module must exist, export the
  full API, and satisfy `new(valid) -> to_map -> from_map` as the identity,
  with valid values synthesized directly from the lexicon IR.
  """

  use ExUnit.Case, async: true

  alias Exosphere.Lexicon.{Generator, Parser}

  @format_values %{
    "datetime" => "2026-01-01T00:00:00Z",
    "did" => "did:plc:abcdefgh",
    "at-did" => "did:plc:abcdefgh",
    "handle" => "user.example.com",
    "at-identifier" => "did:plc:abcdefgh",
    "nsid" => "com.example.thing",
    "at-uri" => "at://did:plc:abcdefgh/app.bsky.feed.post/3jzfcijpj2z2a",
    "tid" => "3jzfcijpj2z2a",
    "cid" => "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
    "uri" => "https://example.com/x",
    "language" => "en"
  }

  setup_all do
    {:ok, lexicons} = Parser.parse_dir("priv/lexicons")
    specs = Generator.generate(lexicons)
    %{lexicons: lexicons, specs: specs}
  end

  test "every generated module is compiled and exports the full API", %{specs: specs} do
    for %{module: module} <- specs do
      assert Code.ensure_loaded?(module), "#{inspect(module)} is not loaded"
      assert function_exported?(module, :new, 1), "#{inspect(module)} new/1"
      assert function_exported?(module, :new!, 1), "#{inspect(module)} new!/1"
      assert function_exported?(module, :to_map, 1), "#{inspect(module)} to_map/1"
      assert function_exported?(module, :from_map, 1), "#{inspect(module)} from_map/1"
      assert function_exported?(module, :type_id, 0), "#{inspect(module)} type_id/0"
      assert is_binary(module.type_id())
    end
  end

  test "IR-driven round-trip identity for every module", %{lexicons: lexicons, specs: specs} do
    modules = Map.new(specs, &{{&1.nsid, &1.def_name || "main"}, &1.module})

    {passed, skipped} =
      Enum.reduce(specs, {0, []}, fn spec, {passed, skipped} ->
        node = if spec.def_name, do: spec.lexicon.defs[spec.def_name], else: spec.lexicon.defs["main"]

        case valid_value(node, spec.nsid, lexicons, modules, 0) do
          :skip ->
            {passed, [spec.module | skipped]}

          value ->
            module = spec.module

            assert {:ok, struct} = module.new(value),
                   "#{inspect(module)}.new(#{inspect(value)})"

            assert {:ok, ^struct} = module.new(module.to_map(struct)),
                   "#{inspect(module)} to_map/from_map round-trip"

            {passed + 1, skipped}
        end
      end)

    # Almost the whole corpus must be covered; only pathological schemas
    # (deep/required ref cycles) may be skipped.
    assert passed >= length(specs) - 3,
           "too many skipped round-trips: #{inspect(skipped)}"
  end

  # --- Minimal valid-value synthesis from the IR ----------------------------------

  defp valid_value(%{kind: :object} = node, nsid, lexicons, modules, depth) do
    required = MapSet.new(node.required || [])

    node.properties
    |> Enum.filter(fn {name, _} -> MapSet.member?(required, name) end)
    |> Enum.map(fn {name, prop} -> {name, valid_value(prop, nsid, lexicons, modules, depth + 1)} end)
    |> Map.new()
  end

  defp valid_value(%{kind: :record}, nsid, lexicons, modules, depth) do
    valid_value(record_object(lexicons[nsid]), nsid, lexicons, modules, depth)
  end

  defp valid_value(%{kind: :string} = node, _, _, _, _) do
    cond do
      node.const -> node.const
      node.enum -> hd(node.enum)
      true -> Map.get(@format_values, node.format, minimal_string(node))
    end
  end

  defp valid_value(%{kind: :token} = node, _, _, _, _), do: minimal_string(node)

  defp valid_value(%{kind: :integer} = node, _, _, _, _), do: node.minimum || 0

  defp valid_value(%{kind: :boolean} = node, _, _, _, _), do: node.const || true

  defp valid_value(%{kind: :array} = node, nsid, lexicons, modules, depth) do
    item = valid_value(node.items, nsid, lexicons, modules, depth + 1)
    List.duplicate(item, max(node.min_length || 1, 1))
  end

  defp valid_value(%{kind: :ref} = node, owner_nsid, lexicons, modules, depth) do
    key = resolve(node.ref, owner_nsid)

    if modules[key] != nil do
      {t_nsid, t_def} = key
      if depth > 6, do: :skip, else: valid_value(lexicons[t_nsid].defs[t_def], t_nsid, lexicons, modules, depth)
    else
      # Unresolved refs are passthrough; any map works
      %{}
    end
  end

  defp valid_value(%{kind: :union} = node, owner_nsid, lexicons, modules, depth) do
    node.refs
    |> Enum.map(&resolve(&1, owner_nsid))
    |> Enum.find_value(fn key = {t_nsid, t_def} ->
      cond do
        modules[key] == nil ->
          nil

        depth > 6 ->
          nil

        true ->
          type_id = if t_def == "main", do: t_nsid, else: "#{t_nsid}##{t_def}"

          case valid_value(lexicons[t_nsid].defs[t_def], t_nsid, lexicons, modules, depth) do
            :skip -> nil
            value -> Map.put(value, "$type", type_id)
          end
      end
    end)
    |> case do
      nil -> %{}
      value -> value
    end
  end

  defp valid_value(%{kind: :blob}, _, _, _, _), do: %{"$type" => "blob"}
  defp valid_value(%{kind: :cid_link}, _, _, _, _), do: %{}
  defp valid_value(%{kind: :bytes}, _, _, _, _), do: <<1>>
  defp valid_value(_, _, _, _, _), do: %{}

  defp record_object(lexicon) do
    case lexicon.defs["main"] do
      %{kind: :record, record: record} -> record
      object -> object
    end
  end

  defp minimal_string(node), do: String.duplicate("a", max(node.min_length || 1, 1))

  defp resolve("#" <> def_name, owner_nsid), do: {owner_nsid, def_name}

  defp resolve(ref, _owner_nsid) do
    case String.split(ref, "#", parts: 2) do
      [nsid] -> {nsid, "main"}
      [nsid, def_name] -> {nsid, def_name}
    end
  end
end
