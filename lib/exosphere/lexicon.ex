defmodule Exosphere.Lexicon do
  @moduledoc """
  Registering, type-checking, and publishing lexicons.

  This module is the entry point for the lexicon workflow; the pieces
  live in their own modules:

  - `Lexicon.Parser` — lexicon JSON → normalized IR
  - `Lexicon.Schema` — the `com.atproto.lexicon.schema` record type
  - `Lexicon.Validator` — runtime validation of values against schemas
  - `Lexicon.Registry` — runtime NSID → lexicon registry
  - `Lexicon.Resolver` — fetching published lexicons from a PDS
  - `Lexicon.Generator` + `mix exosphere.gen.lexicons` — compile-time
    typed modules

  ## The workflow

      # 1. Define (or fetch) a lexicon document
      {:ok, schema} = Exosphere.Lexicon.Schema.new(%{
        "lexicon" => 1,
        "id" => "com.example.post",
        "defs" => %{"main" => %{
          "type" => "record", "key" => "tid",
          "record" => %{"type" => "object",
            "required" => ["text"],
            "properties" => %{"text" => %{"type" => "string", "maxGraphemes" => 100}}}
        }}
      })

      # 2. Type-check records against it — now, and at runtime
      :ok = Exosphere.Lexicon.register(schema)
      :ok = Exosphere.Lexicon.validate("com.example.post", %{
        "$type" => "com.example.post", "text" => "hello"
      })

      # 3. Publish it to a PDS (record key = the NSID)
      {:ok, %{uri: uri, cid: cid}} =
        Exosphere.Lexicon.publish(session, pds_url, did, schema)

  ## Publishing and updating

  `publish/4` writes to `com.atproto.lexicon.schema` with the lexicon's
  NSID as the record key, so publishing an updated document for the same
  NSID overwrites the previous version.
  """

  alias Exosphere.ATProto.Repo
  alias Exosphere.Lexicon.{Parser, Registry, Schema, Validator}

  @doc """
  Register a lexicon (parsed, or a raw JSON document) in the runtime
  `Lexicon.Registry`. See `Exosphere.Lexicon.Registry.register/1`.
  """
  defdelegate register(lexicon), to: Registry

  @doc "Register many lexicons at once. See `Exosphere.Lexicon.Registry.register_all/1`."
  defdelegate register_all(lexicons), to: Registry

  @doc """
  Type-check a value against a registered lexicon.

  `type` is an NSID or NSID with fragment; `value` is the wire-format
  map. Options are forwarded to `Validator.validate/4` (notably
  `strict: true` to reject unknown fields, open-union variants, and
  refs whose target lexicon is not registered).
  See `Exosphere.Lexicon.Registry.validate/3`.
  """
  defdelegate validate(type, value, opts \\ []), to: Registry

  @doc """
  Type-check a value against a schema without registering it.

  Takes a `%Lexicon.Schema{}` (or its parsed IR) — for checking a
  fetched document without touching global registry state. Options are
  forwarded to `Validator.validate/4`.
  """
  @spec validate_with(Schema.t() | Parser.lexicon(), term(), String.t(), [Validator.opt()]) ::
          :ok | {:error, [{path :: String.t(), message :: String.t()}]}
  def validate_with(schema_or_parsed, value, def_name \\ "main", opts \\ [])

  def validate_with(%Schema{parsed: parsed}, value, def_name, opts),
    do: Validator.validate(value, parsed, def_name, opts)

  def validate_with(%{id: _} = parsed, value, def_name, opts),
    do: Validator.validate(value, parsed, def_name, opts)

  @doc """
  Publish a lexicon to a PDS as a `com.atproto.lexicon.schema` record.

  `publish(session, schema)` takes the PDS URL and DID from the session
  (`session.pds` / `session.sub`); `publish(session, pds_url, did,
  schema)` overrides them explicitly.

  The record key is the lexicon's NSID, so the record lands at
  `at://<did>/com.atproto.lexicon.schema/<nsid>` and re-publishing an
  updated document updates it in place.
  """
  @spec publish(map(), Schema.t() | map()) ::
          {:ok, %{uri: String.t(), cid: String.t()}} | {:error, term()}
  def publish(session, schema_or_doc) do
    pds_url = Map.get(session, :pds) || raise ArgumentError, "session has no :pds"
    did = Map.get(session, :sub) || raise ArgumentError, "session has no :sub"
    publish(session, pds_url, did, schema_or_doc)
  end

  @spec publish(map(), String.t(), String.t(), Schema.t() | map()) ::
          {:ok, %{uri: String.t(), cid: String.t()}} | {:error, term()}
  def publish(session, pds_url, did, schema_or_doc) do
    with {:ok, schema} <- to_schema(schema_or_doc) do
      Repo.put_record(
        session,
        pds_url,
        did,
        Schema.collection(),
        Schema.record_key(schema),
        Schema.to_record(schema)
      )
    end
  end

  @doc """
  Delete a published lexicon record by NSID.

  Like `publish/2`, `delete(session, nsid)` reads the PDS URL and DID
  from the session.
  """
  @spec delete(map(), String.t()) :: {:ok, map()} | {:error, term()}
  def delete(session, nsid) do
    pds_url = Map.get(session, :pds) || raise ArgumentError, "session has no :pds"
    did = Map.get(session, :sub) || raise ArgumentError, "session has no :sub"
    delete(session, pds_url, did, nsid)
  end

  @spec delete(map(), String.t(), String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def delete(session, pds_url, did, nsid) do
    Repo.delete_record(session, pds_url, did, Schema.collection(), nsid)
  end

  defp to_schema(%Schema{} = schema), do: {:ok, schema}
  defp to_schema(doc) when is_map(doc), do: Schema.new(doc)
end
