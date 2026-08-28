defmodule Exosphere.ATProto.Identity.DID.PLC.Operation do
  @moduledoc """
  Construction and validation of did:plc operations.

  An operation is a plain map with string keys — the shape the directory
  serves and the shape DAG-CBOR encodes — rather than a struct, because the
  *bytes* are what a DID is derived from and what a signature covers. Keeping
  the map verbatim means a fetched operation round-trips without a lossy
  conversion in the middle.

  ## Operation types

  - `"plc_operation"` — the modern operation, carrying `alsoKnownAs`,
    `verificationMethods`, `rotationKeys` and `services`.
  - `"plc_tombstone"` — permanently deactivates the DID. Carries only
    `type`, `prev` and `sig`; it cannot record a move target.
  - `"create"` — the legacy genesis form, still present in real audit logs
    (see `log_legacy_dholms.json`). Accepted for validation and normalized
    by `normalize/1`; never emitted.

  ## Strictness

  The directory tolerates no extra fields, and neither do we: `validate/1`
  rejects any key outside the type's fixed set. `rotationKeys` must hold 1–5
  unique `did:key`s on secp256k1 or P-256 — the only two curves the method
  permits for rotation — and `services` keys carry no `#` prefix.

  `prev` is *explicitly* `null` for a genesis operation. It is present and
  null, never omitted; an omitted `prev` changes the DAG-CBOR bytes and
  therefore the DID.
  """

  alias Exosphere.ATProto.CBOR
  alias Exosphere.ATProto.Crypto

  @type t :: %{required(String.t()) => term()}

  @operation_type "plc_operation"
  @tombstone_type "plc_tombstone"
  @legacy_type "create"

  @operation_fields ~w(type alsoKnownAs verificationMethods rotationKeys services prev sig)
  @tombstone_fields ~w(type prev sig)
  @legacy_fields ~w(type handle service signingKey recoveryKey prev sig)

  @max_rotation_keys 5

  # Rotation keys are restricted to these two curves by the method spec, even
  # though verification methods accept any syntactically valid did:key.
  @rotation_curves [:secp256k1, :p256]

  @type build_opts :: [
          also_known_as: [String.t()],
          verification_methods: %{String.t() => String.t()},
          rotation_keys: [String.t()],
          services: %{String.t() => %{String.t() => String.t()}},
          prev: String.t() | nil
        ]

  @doc """
  Build an unsigned `plc_operation`.

  Returns the operation without a `sig` key — pass it to
  `Exosphere.ATProto.Identity.DID.PLC.Signer.sign/3`.

  ## Options

  - `:also_known_as` — URIs, e.g. `["at://alice.example.com"]` (no duplicates)
  - `:verification_methods` — map of service id (no `#`) to `did:key`
  - `:rotation_keys` — 1–5 unique `did:key`s, highest authority first
  - `:services` — map of service id (no `#`) to `%{"type" => _, "endpoint" => _}`
  - `:prev` — CID string of the previous operation, or `nil` for genesis

  ## Examples

      iex> {:ok, op} = Operation.new(rotation_keys: ["did:key:zQ3sh..."], prev: nil)
      iex> op["prev"]
      nil
  """
  @spec new(build_opts()) :: {:ok, t()} | {:error, term()}
  def new(opts) do
    op = %{
      "type" => @operation_type,
      "alsoKnownAs" => Keyword.get(opts, :also_known_as, []),
      "verificationMethods" => Keyword.get(opts, :verification_methods, %{}),
      "rotationKeys" => Keyword.get(opts, :rotation_keys, []),
      "services" => Keyword.get(opts, :services, %{}),
      "prev" => Keyword.get(opts, :prev)
    }

    with :ok <- validate(op), do: {:ok, op}
  end

  @doc """
  Build an unsigned `plc_tombstone` pointing at `prev`.

  A tombstone permanently deactivates the DID. It carries no data fields, so
  it cannot record where an identity moved to — that record has to live
  somewhere else.
  """
  @spec new_tombstone(String.t()) :: {:ok, t()} | {:error, term()}
  def new_tombstone(prev) when is_binary(prev) do
    {:ok, %{"type" => @tombstone_type, "prev" => prev}}
  end

  def new_tombstone(_), do: {:error, :tombstone_requires_prev}

  @doc """
  Validate an operation's shape.

  Checks the field set is exactly the one its type permits, that `prev` is
  present (possibly null), and — for `plc_operation` — the `alsoKnownAs`,
  `rotationKeys`, `verificationMethods` and `services` rules.

  Signature validity is a separate question; see
  `Exosphere.ATProto.Identity.DID.PLC.Signer.verify/3`.
  """
  @spec validate(t()) :: :ok | {:error, term()}
  def validate(%{"type" => @operation_type} = op) do
    with :ok <- validate_fields(op, @operation_fields),
         :ok <- validate_prev(op),
         :ok <- validate_also_known_as(op),
         :ok <- validate_rotation_keys(op),
         :ok <- validate_verification_methods(op) do
      validate_services(op)
    end
  end

  def validate(%{"type" => @tombstone_type} = op) do
    with :ok <- validate_fields(op, @tombstone_fields) do
      case Map.get(op, "prev") do
        prev when is_binary(prev) -> :ok
        _ -> {:error, :tombstone_requires_prev}
      end
    end
  end

  def validate(%{"type" => @legacy_type} = op) do
    with :ok <- validate_fields(op, @legacy_fields),
         :ok <- validate_prev(op),
         :ok <- validate_rotation_key(op["recoveryKey"]) do
      validate_rotation_key(op["signingKey"])
    end
  end

  def validate(%{"type" => other}), do: {:error, {:unknown_operation_type, other}}
  def validate(_), do: {:error, :missing_operation_type}

  @doc """
  Normalize a legacy `create` operation into the modern `plc_operation` shape.

  Modern operations are returned unchanged. **The normalized form is for
  interpretation only** — never hash or verify it, because a legacy
  operation's DID and signature are derived from its own original bytes.
  """
  @spec normalize(t()) :: t()
  def normalize(%{"type" => @legacy_type} = op) do
    %{
      "type" => @operation_type,
      "alsoKnownAs" => ["at://" <> to_string(op["handle"])],
      "verificationMethods" => %{"atproto" => op["signingKey"]},
      "rotationKeys" => [op["recoveryKey"], op["signingKey"]],
      "services" => %{
        "atproto_pds" => %{
          "type" => "AtprotoPersonalDataServer",
          "endpoint" => op["service"]
        }
      },
      "prev" => Map.get(op, "prev"),
      "sig" => Map.get(op, "sig")
    }
  end

  def normalize(op), do: op

  @doc """
  The rotation keys that may sign the *next* operation after this one.

  Legacy operations are normalized first, so a `create` yields
  `[recoveryKey, signingKey]` in that authority order.
  """
  @spec rotation_keys(t()) :: [String.t()]
  def rotation_keys(op) do
    op |> normalize() |> Map.get("rotationKeys", [])
  end

  @doc """
  The DAG-CBOR bytes an operation's signature covers: the operation with
  `sig` **omitted entirely** (not nulled).

  `prev` is left as the string CID it already is — DAG-CBOR string-encodes
  it rather than emitting an IPLD link, which is the trap this function
  exists to avoid re-introducing.
  """
  @spec unsigned_bytes(t()) :: {:ok, binary()} | {:error, term()}
  def unsigned_bytes(op) when is_map(op) do
    op |> Map.delete("sig") |> CBOR.encode()
  end

  @doc """
  The DAG-CBOR bytes of a complete, signed operation — what its CID and, for
  a genesis operation, its DID are derived from.
  """
  @spec signed_bytes(t()) :: {:ok, binary()} | {:error, term()}
  def signed_bytes(op) when is_map(op), do: CBOR.encode(op)

  @doc "Is this operation a genesis (no predecessor)?"
  @spec genesis?(t()) :: boolean()
  def genesis?(op), do: is_nil(Map.get(op, "prev"))

  @doc "Is this operation a tombstone?"
  @spec tombstone?(t()) :: boolean()
  def tombstone?(%{"type" => @tombstone_type}), do: true
  def tombstone?(_), do: false

  # -- validation helpers ----------------------------------------------------

  defp validate_fields(op, allowed) do
    case Map.keys(op) -- allowed do
      [] -> :ok
      extra -> {:error, {:unexpected_fields, Enum.sort(extra)}}
    end
  end

  # `prev` must be *present* — null is a value here, not an absence. An
  # omitted prev encodes to different bytes and so yields a different DID.
  defp validate_prev(op) do
    cond do
      not Map.has_key?(op, "prev") -> {:error, :missing_prev}
      is_nil(op["prev"]) or is_binary(op["prev"]) -> :ok
      true -> {:error, :invalid_prev}
    end
  end

  defp validate_also_known_as(%{"alsoKnownAs" => akas}) when is_list(akas) do
    cond do
      not Enum.all?(akas, &is_binary/1) -> {:error, :invalid_also_known_as}
      duplicates?(akas) -> {:error, :duplicate_also_known_as}
      true -> :ok
    end
  end

  defp validate_also_known_as(_), do: {:error, :invalid_also_known_as}

  defp validate_rotation_keys(%{"rotationKeys" => keys}) when is_list(keys) do
    cond do
      keys == [] ->
        {:error, :empty_rotation_keys}

      length(keys) > @max_rotation_keys ->
        {:error, :too_many_rotation_keys}

      duplicates?(keys) ->
        {:error, :duplicate_rotation_keys}

      true ->
        Enum.reduce_while(keys, :ok, fn key, :ok ->
          case validate_rotation_key(key) do
            :ok -> {:cont, :ok}
            error -> {:halt, error}
          end
        end)
    end
  end

  defp validate_rotation_keys(_), do: {:error, :invalid_rotation_keys}

  # Rotation keys are limited to secp256k1 and P-256; verification methods are
  # not (relaxed upstream in June 2025).
  #
  # `Crypto.from_did_key/1` already answers `:unsupported_key_type` for any
  # other multicodec, so parsing *is* the curve check — the guard below states
  # the rule rather than adding a second one.
  defp validate_rotation_key(key) when is_binary(key) do
    case Crypto.from_did_key(key) do
      {:ok, _pub, curve} when curve in @rotation_curves -> :ok
      {:error, reason} -> {:error, {:invalid_rotation_key, reason}}
    end
  end

  defp validate_rotation_key(_), do: {:error, :invalid_rotation_key}

  defp validate_verification_methods(%{"verificationMethods" => methods}) when is_map(methods) do
    Enum.reduce_while(methods, :ok, fn {id, key}, :ok ->
      cond do
        not is_binary(id) or String.contains?(id, "#") ->
          {:halt, {:error, {:invalid_verification_method_id, id}}}

        not is_binary(key) or not String.starts_with?(key, "did:key:") ->
          {:halt, {:error, {:invalid_verification_method, id}}}

        true ->
          {:cont, :ok}
      end
    end)
  end

  defp validate_verification_methods(_), do: {:error, :invalid_verification_methods}

  defp validate_services(%{"services" => services}) when is_map(services) do
    Enum.reduce_while(services, :ok, fn {id, service}, :ok ->
      cond do
        not is_binary(id) or String.contains?(id, "#") ->
          {:halt, {:error, {:invalid_service_id, id}}}

        not is_map(service) or not is_binary(service["type"]) or
            not is_binary(service["endpoint"]) ->
          {:halt, {:error, {:invalid_service, id}}}

        true ->
          {:cont, :ok}
      end
    end)
  end

  defp validate_services(_), do: {:error, :invalid_services}

  defp duplicates?(list), do: length(Enum.uniq(list)) != length(list)
end
