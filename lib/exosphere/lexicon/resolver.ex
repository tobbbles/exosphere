defmodule Exosphere.Lexicon.Resolver do
  @moduledoc """
  Fetching lexicons published as `com.atproto.lexicon.schema` records.

  Two resolution paths:

  - **Direct**: `fetch/3` against a known PDS and DID — the record key
    is the lexicon NSID, so a single `com.atproto.repo.getRecord` call
    retrieves the document.
  - **Authority**: `resolve/2` follows the lexicon resolution spec: the
    NSID's authority domain is looked up as a DNS TXT record
    (`_lexicon.<reversed-domain>` → `did=<DID>`), the DID is resolved to
    its PDS, and the schema record fetched from there. Resolution is
    deliberately non-recursive: if the TXT lookup fails, resolution
    fails (per spec, resolvers must not probe up or down the DNS tree).

  Both paths validate the fetched document (`Lexicon.Schema.new/1`) and
  can register it in `Lexicon.Registry` with `register: true`.

  ## Examples

      # From a known repo
      {:ok, schema} =
        Exosphere.Lexicon.Resolver.fetch("https://pds.example.com",
          "did:plc:abc123", "com.example.post", register: true)

      # Via NSID authority
      {:ok, schema} = Exosphere.Lexicon.Resolver.resolve("com.example.post")

      # Every lexicon a repo publishes
      {:ok, schemas} = Exosphere.Lexicon.Resolver.list("https://pds.example.com", "did:plc:abc123")
  """

  alias Exosphere.ATProto.{HTTP, Identity.DID, NSID, XRPC.Client}
  alias Exosphere.Lexicon.{Registry, Schema}

  @default_limit 100

  @type fetch_opt :: {:register, boolean()} | {:http, module()}

  @doc """
  Fetch a lexicon by NSID from a specific repository.

  Options:

  - `:register` — register the fetched lexicon in `Lexicon.Registry`
    (default `false`)
  - `:http` — HTTP client module implementing `HTTP.Behaviour`
  """
  @spec fetch(String.t(), DID.did(), String.t(), [fetch_opt()]) ::
          {:ok, Schema.t()} | {:error, term()}
  def fetch(pds_url, did, nsid, opts \\ []) do
    with {:ok, %{"value" => value}} <-
           Client.query(client(pds_url, opts), "com.atproto.repo.getRecord",
             repo: did,
             collection: Schema.collection(),
             rkey: nsid
           ),
         {:ok, schema} <- Schema.from_record(value) do
      maybe_register(schema, opts)
    end
  end

  @doc """
  List every lexicon published by a repository, paginating through
  `com.atproto.repo.listRecords`.

  Returns `{:ok, %{schemas: [Schema.t()], invalid: [nsid]}}` — records
  that fail `Lexicon.Schema` validation are skipped, with their NSIDs
  reported under `:invalid`.
  """
  @spec list(String.t(), DID.did(), [fetch_opt()]) ::
          {:ok, %{schemas: [Schema.t()], invalid: [String.t()]}} | {:error, term()}
  def list(pds_url, did, opts \\ []) do
    with {:ok, values} <- list_all(pds_url, did, opts) do
      {schemas, invalid} =
        Enum.reduce(values, {[], []}, fn value, {ok, bad} ->
          case Schema.from_record(value) do
            {:ok, schema} ->
              maybe_register(schema, opts)
              {[schema | ok], bad}

            {:error, _} ->
              {ok, [Map.get(value, "id", Map.get(value, "rkey", "unknown")) | bad]}
          end
        end)

      {:ok, %{schemas: Enum.reverse(schemas), invalid: Enum.reverse(invalid)}}
    end
  end

  defp list_all(pds_url, did, opts, cursor \\ nil, acc \\ []) do
    params =
      %{repo: did, collection: Schema.collection(), limit: @default_limit}
      |> then(&if cursor, do: Map.put(&1, :cursor, cursor), else: &1)

    case Client.query(client(pds_url, opts), "com.atproto.repo.listRecords", params) do
      {:ok, %{"records" => records} = response} ->
        values = Enum.map(records, & &1["value"])
        acc = acc ++ values

        if response["cursor"] && records != [],
          do: list_all(pds_url, did, opts, response["cursor"], acc),
          else: {:ok, acc}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Resolve a lexicon by NSID authority: DNS TXT `_lexicon.<domain>` →
  DID → PDS → schema record.

  Options: `fetch/4` options plus `:http` (used for both DNS-adjacent
  DID resolution and the PDS fetch).
  """
  @spec resolve(String.t(), [fetch_opt()]) :: {:ok, Schema.t()} | {:error, term()}
  def resolve(nsid, opts \\ []) do
    with {:ok, authority} <- authority_of(nsid),
         {:ok, did} <- authority_did(authority),
         {:ok, doc} <- DID.resolve(did, http_client: Keyword.get(opts, :http, HTTP)),
         {:ok, pds_url} <- DID.get_pds_endpoint(doc) do
      fetch(pds_url, did, nsid, opts)
    end
  end

  # The NSID authority is the domain reversed: "com.example.post" has
  # authority "com.example" → lookup name "_lexicon.example.com".
  defp authority_of(nsid) do
    case NSID.parse(nsid) do
      {:ok, %{authority: authority}} -> {:ok, authority}
      _ -> {:error, {:invalid_nsid, nsid}}
    end
  end

  defp authority_did(authority) do
    domain = authority |> String.split(".") |> Enum.reverse() |> Enum.join(".")
    query = ~c"_lexicon.#{domain}"

    case :inet_res.lookup(query, :in, :txt, [], 5_000) do
      [] ->
        {:error, {:no_lexicon_txt_record, domain}}

      records ->
        records
        |> Enum.flat_map(& &1)
        |> Enum.map(&to_string/1)
        |> Enum.find(&String.starts_with?(&1, "did="))
        |> case do
          "did=" <> did -> {:ok, String.trim(did)}
          nil -> {:error, {:no_did_in_txt_record, domain}}
        end
    end
  rescue
    _ -> {:error, :dns_lookup_failed}
  end

  defp maybe_register(schema, opts) do
    if Keyword.get(opts, :register, false), do: Registry.register(schema.parsed)
    {:ok, schema}
  end

  defp client(pds_url, opts) do
    case Keyword.get(opts, :http) do
      nil -> Client.new(pds_url)
      http -> Client.new(pds_url, http: http)
    end
  end
end
