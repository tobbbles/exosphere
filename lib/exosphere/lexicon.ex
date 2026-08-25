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
  alias Exosphere.Lexicon.{Registry, Schema}

  @doc """
  Register a lexicon (parsed, or a raw JSON document) in the runtime
  `Lexicon.Registry`. See `Registry.register/1`.
  """
  defdelegate register(lexicon), to: Registry

  @doc "Register many lexicons at once. See `Registry.register_all/1`."
  defdelegate register_all(lexicons), to: Registry

  @doc """
  Type-check a value against a registered lexicon.

  `type` is an NSID or NSID with fragment; `value` is the wire-format
  map. Options are forwarded to `Validator.validate/4` (notably
  `strict: true` to reject unknown fields and open-union variants).
  See `Registry.validate/3`.
  """
  defdelegate validate(type, value, opts \\ []), to: Registry

  @doc """
  Publish a lexicon to a PDS as a `com.atproto.lexicon.schema` record.

  The record key is the lexicon's NSID, so the record lands at
  `at://<did>/com.atproto.lexicon.schema/<nsid>` and re-publishing an
  updated document updates it in place.
  """
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

  @doc "Delete a published lexicon record by NSID."
  @spec delete(map(), String.t(), String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def delete(session, pds_url, did, nsid) do
    Repo.delete_record(session, pds_url, did, Schema.collection(), nsid)
  end

  defp to_schema(%Schema{} = schema), do: {:ok, schema}
  defp to_schema(doc) when is_map(doc), do: Schema.new(doc)
end
