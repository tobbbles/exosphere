defmodule Exosphere.Lexicon.Registry do
  @moduledoc """
  A runtime registry of lexicons, keyed by NSID.

  The registry backs `Lexicon.Validator`'s cross-lexicon ref resolution:
  a lexicon only needs to be registered for refs pointing at it (e.g. a
  union variant `com.example.foo#item`) to fully validate.

  State lives in `:persistent_term` — no process or supervision needed —
  which suits the read-heavy, rarely-written profile of a schema cache.
  For bigger dynamic sets (thousands of runtime-registered lexicons),
  swap in a custom registry module via the validator's `:registry` opt;
  any module implementing `fetch/1` works.

  ## Examples

      {:ok, lexicon} = Exosphere.Lexicon.Parser.parse_file("my-lexicon.json")
      :ok = Exosphere.Lexicon.Registry.register(lexicon)

      {:ok, lexicon} = Exosphere.Lexicon.Registry.fetch("com.example.post")

      :ok = Exosphere.Lexicon.Registry.validate(
        "com.example.post", %{"$type" => "com.example.post", "text" => "hi"})
  """

  alias Exosphere.Lexicon.{Parser, Schema, Validator}

  @table_key __MODULE__

  @doc """
  Register a lexicon: a parsed lexicon, a `%Lexicon.Schema{}` struct (as
  from `Schema.new/1` or `Resolver.fetch/4`), or a raw lexicon JSON map
  (which is parsed and validated first).

  Later registrations for the same NSID replace earlier ones.
  """
  @spec register(Parser.lexicon() | Schema.t() | map()) ::
          :ok | {:error, [{path :: String.t(), message :: String.t()}]}

  # %Schema{} also matches the map clause below (it has an :id key), but
  # stores the struct where parsed IR belongs — every later validation
  # against it would fail. Unwrap it first.
  def register(%Schema{parsed: parsed}) when parsed != nil, do: register(parsed)

  def register(%{id: _} = lexicon) do
    :persistent_term.put(@table_key, Map.put(all(), lexicon.id, lexicon))
    :ok
  end

  def register(json) when is_map(json) do
    case Parser.parse(json) do
      {:ok, lexicon} -> register(lexicon)
      {:error, reason} -> {:error, [{"", "invalid lexicon: #{inspect(reason)}"}]}
    end
  end

  @doc """
  Register many lexicons at once, stopping at the first error.

  Accepts any enumerable of lexicons (parsed, `%Schema{}`, or raw JSON
  maps) — including the `%{nsid => lexicon}` map returned by
  `Parser.parse_dir/1`.
  """
  @spec register_all(Enumerable.t() | map()) :: :ok | {:error, term()}
  # A parse_dir/1 result map enumerates as {nsid, lexicon} tuples;
  # normalize it (a parsed lexicon never has a binary `:id`).
  def register_all(lexicons) when is_map(lexicons) and not is_struct(lexicons),
    do: register_all(Map.values(lexicons))

  def register_all(lexicons) do
    Enum.reduce_while(lexicons, :ok, fn lexicon, :ok ->
      case register(lexicon) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  @doc """
  Register every lexicon JSON file under `dir` (recursively).

  Returns `{:ok, nsids}` or `{:error, {path, reason}}` for the first file
  that fails to parse. Host applications can point this at their own
  `priv/lexicons`.
  """
  @spec load_dir(Path.t()) :: {:ok, [String.t()]} | {:error, term()}
  def load_dir(dir) do
    case Parser.parse_dir(dir) do
      {:ok, lexicons} ->
        register_all(lexicons)
        {:ok, Map.keys(lexicons)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc "Load every vendored lexicon under the application's `priv/lexicons`."
  @spec load_vendored() :: {:ok, [String.t()]} | {:error, term()}
  def load_vendored, do: load_dir(Application.app_dir(:exosphere, "priv/lexicons"))

  @doc "Fetch a registered lexicon by NSID."
  @spec fetch(String.t()) :: {:ok, Parser.lexicon()} | :error
  def fetch(nsid) do
    case Map.fetch(all(), nsid) do
      {:ok, lexicon} -> {:ok, lexicon}
      :error -> :error
    end
  end

  @doc "Whether an NSID is registered."
  @spec registered?(String.t()) :: boolean()
  def registered?(nsid), do: Map.has_key?(all(), nsid)

  @doc "All registered NSIDs, sorted."
  @spec list() :: [String.t()]
  def list, do: all() |> Map.keys() |> Enum.sort()

  @doc "Remove a lexicon from the registry."
  @spec unregister(String.t()) :: :ok
  def unregister(nsid) do
    :persistent_term.put(@table_key, Map.delete(all(), nsid))
    :ok
  end

  @doc "Clear the registry. Intended for tests and repl sessions."
  @spec reset() :: :ok
  def reset do
    :persistent_term.put(@table_key, %{})
    :ok
  end

  @doc """
  Validate a value against a registered lexicon.

  `type` is an NSID (`"com.example.post"`) or NSID with fragment
  (`"com.example.post#item"`). Options are passed to `Validator.validate/4`.

  With `optimistic: true`, an unregistered NSID passes without
  validation, mirroring the PDS "fail-open" record-creation mode.
  """
  @spec validate(String.t(), term(), keyword()) ::
          :ok | {:error, [{path :: String.t(), message :: String.t()}]}
  def validate(type, value, opts \\ []) do
    {nsid, def_name} = split_type(type)

    case fetch(nsid) do
      {:ok, lexicon} ->
        Validator.validate(value, lexicon, def_name, opts)

      :error ->
        if Keyword.get(opts, :optimistic, false),
          do: :ok,
          else: {:error, [{"", "no lexicon registered for #{nsid}"}]}
    end
  end

  @doc """
  Validate a record map (with `$type`) against its registered lexicon.
  """
  @spec validate_record(String.t(), term(), keyword()) ::
          :ok | {:error, [{path :: String.t(), message :: String.t()}]}
  def validate_record(type, value, opts \\ []) do
    {nsid, _} = split_type(type)

    case fetch(nsid) do
      {:ok, lexicon} -> Validator.validate_record(value, lexicon, opts)
      :error -> {:error, [{"", "no lexicon registered for #{nsid}"}]}
    end
  end

  defp split_type(type) do
    case String.split(type, "#", parts: 2) do
      [nsid] -> {nsid, "main"}
      [nsid, def_name] -> {nsid, def_name}
    end
  end

  defp all, do: :persistent_term.get(@table_key, %{})
end
