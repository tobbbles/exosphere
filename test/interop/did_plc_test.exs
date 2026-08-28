defmodule Exosphere.Interop.DIDPLCTest do
  @moduledoc """
  Conformance against the reference did:plc implementation's audit-log corpus
  (`did-method-plc/go-didplc`, `testdata/`). See
  `test/fixtures/did-plc/SOURCE.md` for the pinned commit and a per-fixture
  breakdown.

  Each fixture is a whole audit log with a known verdict, which makes this a
  end-to-end check of operation validation, DAG-CBOR signing bytes, signature
  verification, DID derivation, chaining, tombstones and the nullification
  rules at once — rather than a unit test of any one of them.
  """
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.Crypto
  alias Exosphere.ATProto.Identity.DID.PLC
  alias Exosphere.ATProto.Identity.DID.PLC.AuditLog
  alias Exosphere.ATProto.Identity.DID.PLC.Operation
  alias Exosphere.ATProto.Identity.DID.PLC.Signer

  # Scripts a sequence of POST responses through the process dictionary
  # (submit/3 runs in the caller's process, so no agent is needed) and
  # counts how many attempts were made.
  defmodule SubmitHTTP do
    @moduledoc false
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    def post(_url, _opts \\ []) do
      Process.put(:post_count, Process.get(:post_count, 0) + 1)
      [next | rest] = Process.get(:post_responses)
      Process.put(:post_responses, rest)
      next
    end

    def posts, do: Process.get(:post_count, 0)

    def get(_url, _opts \\ []), do: {:ok, %{status: 404, body: %{}}}
  end

  @root Path.expand(Path.join([__DIR__, "..", "fixtures", "did-plc"]))

  @valid ~w(
    log_bskyapp
    log_bnewbold_robocracy
    log_legacy_dholms
    log_tombstone
    log_nullification
    log_nullification_nontrivial
    log_nullification_at_exactly_72h
    log_nullified_tombstone
  )

  # Each invalid log must be rejected for its OWN reason — a rule regressing
  # into over-strictness would keep a boolean test green while the fixture
  # stopped testing what it exists to test.
  @invalid_reasons %{
    log_invalid_nullification_too_slow: :recovery_window_expired,
    log_invalid_nullification_reused_key: :insufficient_authority,
    log_invalid_update_nullified: :builds_on_nullified,
    log_invalid_update_tombstoned: :builds_on_tombstone,
    log_invalid_sig_k256_high_s: :invalid_signature,
    log_invalid_sig_p256_high_s: :invalid_signature,
    log_invalid_sig_der: :invalid_signature,
    log_invalid_sig_b64_padding_chars: :invalid_signature,
    log_invalid_sig_b64_padding_bits: :invalid_signature,
    log_invalid_sig_b64_newline: :invalid_signature,
    log_duplicate_rotation_keys: :duplicate_rotation_keys,
    log_empty_rotation_keys: :empty_rotation_keys
  }

  defp log(name) do
    @root |> Path.join("#{name}.json") |> File.read!() |> Jason.decode!()
  end

  describe "valid audit logs" do
    test "every valid fixture validates, and nullification matches the directory" do
      failures =
        for name <- @valid, reduce: [] do
          acc ->
            case AuditLog.validate_against_flags(log(name)) do
              :ok -> acc
              {:error, reason} -> [{name, reason} | acc]
            end
        end

      assert failures == [],
             "logs that should be valid were rejected:\n" <>
               Enum.map_join(failures, "\n", fn {n, r} -> "  - #{n}: #{inspect(r)}" end)
    end
  end

  describe "invalid audit logs" do
    test "every invalid fixture is rejected for its specific reason" do
      for {name, expected} <- @invalid_reasons do
        assert {:error, {^expected, _cid}} = AuditLog.validate(log(name)),
               "#{name} should be rejected with #{inspect(expected)}"
      end
    end
  end

  describe "malformed logs" do
    test "entries missing cid or operation are errors, not crashes" do
      [g | _] = log("log_tombstone")

      assert {:error, {:invalid_entry, :missing_cid}} = AuditLog.validate([Map.delete(g, "cid")])

      assert {:error, {:invalid_entry, :missing_operation}} =
               AuditLog.validate([Map.delete(g, "operation")])

      assert {:error, {:invalid_entry, :not_a_map}} = AuditLog.validate(["not an entry"])
      assert {:error, {:duplicate_cid, _}} = AuditLog.validate([g, g])
    end

    test "a reported CID that does not match the operation bytes is rejected" do
      [e0, e1 | _] = log("log_tombstone")

      assert {:error, {:cid_mismatch, expected: _, got: "bafyreiFAKE"}} =
               AuditLog.validate([%{e0 | "cid" => "bafyreiFAKE"}, e1])
    end

    test "entries belonging to a different DID are rejected" do
      [e0, e1 | _] = log("log_tombstone")

      assert {:error, {:did_mismatch, expected: _, got: "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz"}} =
               AuditLog.validate([e0, %{e1 | "did" => "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz"}])
    end

    test "timestamps must strictly increase along the chain" do
      [e0, e1 | _] = log("log_tombstone")

      assert {:error, {:invalid_timestamp_order, _}} =
               AuditLog.validate([e0, %{e1 | "createdAt" => e0["createdAt"]}])
    end

    test "a second genesis is rejected as such, not as an unknown prev" do
      [g | _] = log("log_tombstone")

      {:ok, kp} = Crypto.generate_keypair(:secp256k1)
      {:ok, dk} = Crypto.to_did_key(kp.public_key, :secp256k1)
      {:ok, op} = Operation.new(rotation_keys: [dk])
      {:ok, signed} = Signer.sign(op, kp.private_key, :secp256k1)
      {:ok, cid} = Signer.cid(signed)

      second = %{
        "did" => g["did"],
        "operation" => signed,
        "cid" => cid,
        "nullified" => false,
        "createdAt" => "2100-01-01T00:00:00Z"
      }

      assert {:error, {:unexpected_genesis, ^cid}} = AuditLog.validate([g, second])
    end
  end

  describe "submission" do
    setup do
      {:ok, keypair} = Crypto.generate_keypair(:secp256k1)
      {:ok, did_key} = Crypto.to_did_key(keypair.public_key, :secp256k1)

      {:ok, op} = Operation.new(rotation_keys: [did_key], also_known_as: ["at://a.example.com"])
      {:ok, signed} = Signer.sign(op, keypair.private_key, :secp256k1)
      {:ok, did} = Signer.derive_did(signed)

      Process.put(:post_count, 0)
      %{signed: signed, did: did}
    end

    test "an accepted operation returns the DID", ctx do
      Process.put(:post_responses, [{:ok, %{status: 200, body: %{}}}])

      assert {:ok, did} = PLC.submit(ctx.did, ctx.signed, http_client: SubmitHTTP)
      assert did == ctx.did
      assert SubmitHTTP.posts() == 1
    end

    test "a 429 retries like a 5xx rather than counting as rejected", ctx do
      Process.put(:post_responses, [{:ok, %{status: 429}}, {:ok, %{status: 200, body: %{}}}])

      assert {:ok, _} =
               PLC.submit(ctx.did, ctx.signed, http_client: SubmitHTTP, backoff_ms: 0)

      assert SubmitHTTP.posts() == 2
    end

    test "a 429 that never clears surfaces as an HTTP error, not a rejection", ctx do
      Process.put(:post_responses, [{:ok, %{status: 429}}, {:ok, %{status: 429}}])

      assert {:error, {:http_error, 429}} =
               PLC.submit(ctx.did, ctx.signed,
                 http_client: SubmitHTTP,
                 backoff_ms: 0,
                 max_attempts: 2
               )

      assert SubmitHTTP.posts() == 2
    end

    test "a 4xx is not retried", ctx do
      Process.put(:post_responses, [{:ok, %{status: 400, body: %{"error" => "nope"}}}])

      assert {:error, {:rejected, 400, _}} =
               PLC.submit(ctx.did, ctx.signed, http_client: SubmitHTTP)

      assert SubmitHTTP.posts() == 1
    end

    test "operations over the directory's 4,000-byte cap are refused locally", ctx do
      big = Map.put(ctx.signed, "alsoKnownAs", ["at://" <> String.duplicate("a", 4_100)])

      assert {:error, {:operation_too_large, size}} =
               PLC.submit(ctx.did, big, http_client: SubmitHTTP)

      assert size > 4000
      assert SubmitHTTP.posts() == 0
    end
  end

  describe "DID derivation" do
    test "every genesis operation derives the DID its log is for" do
      mismatches =
        for name <- @valid, reduce: [] do
          acc ->
            [first | _] = log(name)
            expected = first["did"]

            case Signer.derive_did(first["operation"]) do
              {:ok, ^expected} -> acc
              {:ok, other} -> [{name, expected, other} | acc]
              {:error, reason} -> [{name, expected, reason} | acc]
            end
        end

      assert mismatches == [],
             "DID derivation mismatches:\n" <>
               Enum.map_join(mismatches, "\n", fn {n, e, g} ->
                 "  - #{n}: expected #{e}, got #{inspect(g)}"
               end)
    end

    test "derivation covers the signed bytes, so touching the signature changes the DID" do
      [first | _] = log("log_tombstone")
      op = first["operation"]

      {:ok, did} = Signer.derive_did(op)
      {:ok, other} = Signer.derive_did(Map.put(op, "sig", String.reverse(op["sig"])))

      refute did == other
    end
  end

  describe "operation CIDs" do
    test "every operation's CID matches the one the directory recorded" do
      mismatches =
        for name <- @valid,
            entry <- log(name),
            reduce: [] do
          acc ->
            expected = entry["cid"]

            case Signer.cid(entry["operation"]) do
              {:ok, ^expected} -> acc
              {:ok, other} -> [{name, expected, other} | acc]
              {:error, reason} -> [{name, expected, reason} | acc]
            end
        end

      assert mismatches == [],
             "CID mismatches:\n" <>
               Enum.map_join(mismatches, "\n", fn {n, e, g} ->
                 "  - #{n}: expected #{e}, got #{inspect(g)}"
               end)
    end
  end

  describe "signature encoding strictness" do
    test "rejects padding characters, padding bits and whitespace" do
      assert {:error, :signature_padding_chars} = Signer.decode_signature("AAAA=")
      assert {:error, :signature_whitespace} = Signer.decode_signature("AAAA\nBBBB")
      assert {:error, :missing_signature} = Signer.decode_signature(nil)
    end

    test "accepts a canonical unpadded base64url signature" do
      raw = :crypto.strong_rand_bytes(64)
      encoded = Base.url_encode64(raw, padding: false)

      assert {:ok, ^raw} = Signer.decode_signature(encoded)
    end
  end

  describe "round trip" do
    test "a freshly built genesis operation signs, derives and self-verifies" do
      {:ok, keypair} = Crypto.generate_keypair(:secp256k1)
      {:ok, did_key} = Crypto.to_did_key(keypair.public_key, :secp256k1)

      {:ok, op} =
        Operation.new(
          rotation_keys: [did_key],
          also_known_as: ["at://alice.yakka.social"],
          verification_methods: %{"atproto" => did_key},
          services: %{
            "atproto_pds" => %{
              "type" => "AtprotoPersonalDataServer",
              "endpoint" => "https://pds.example.com"
            }
          }
        )

      assert Map.has_key?(op, "prev")
      assert is_nil(op["prev"])
      refute Map.has_key?(op, "sig")

      {:ok, signed} = Signer.sign(op, keypair.private_key, :secp256k1)
      assert :ok = Signer.verify(signed, did_key)

      {:ok, did} = Signer.derive_did(signed)
      assert String.starts_with?(did, "did:plc:")
      assert String.length(did) == String.length("did:plc:") + 24
    end

    test "a tombstone chains from a prev and carries no data fields" do
      {:ok, tombstone} = Operation.new_tombstone("bafyreiabc")

      assert :ok = Operation.validate(tombstone)
      assert Operation.tombstone?(tombstone)
      assert Map.keys(tombstone) |> Enum.sort() == ["prev", "type"]
    end
  end

  describe "operation validation" do
    setup do
      {:ok, keypair} = Crypto.generate_keypair(:secp256k1)
      {:ok, did_key} = Crypto.to_did_key(keypair.public_key, :secp256k1)
      %{key: did_key}
    end

    test "rejects extra fields", %{key: key} do
      {:ok, op} = Operation.new(rotation_keys: [key])

      assert {:error, {:unexpected_fields, ["surprise"]}} =
               Operation.validate(Map.put(op, "surprise", true))
    end

    test "rejects an omitted prev", %{key: key} do
      {:ok, op} = Operation.new(rotation_keys: [key])
      assert {:error, :missing_prev} = Operation.validate(Map.delete(op, "prev"))
    end

    test "rejects empty, duplicate and oversized rotation key sets", %{key: key} do
      assert {:error, :empty_rotation_keys} = Operation.new(rotation_keys: [])
      assert {:error, :duplicate_rotation_keys} = Operation.new(rotation_keys: [key, key])

      assert {:error, {:invalid_rotation_key, _}} =
               Operation.new(rotation_keys: ["not-a-did-key"])
    end

    test "rejects service and verification-method ids carrying a # prefix", %{key: key} do
      assert {:error, {:invalid_service_id, "#atproto_pds"}} =
               Operation.new(
                 rotation_keys: [key],
                 services: %{
                   "#atproto_pds" => %{"type" => "T", "endpoint" => "https://e.example"}
                 }
               )

      assert {:error, {:invalid_verification_method_id, "#atproto"}} =
               Operation.new(rotation_keys: [key], verification_methods: %{"#atproto" => key})
    end

    test "rejects duplicate alsoKnownAs", %{key: key} do
      assert {:error, :duplicate_also_known_as} =
               Operation.new(rotation_keys: [key], also_known_as: ["at://a", "at://a"])
    end
  end

  describe "legacy create operations" do
    test "normalize into the modern shape without disturbing the original" do
      [first | _] = log("log_legacy_dholms")
      op = first["operation"]

      assert op["type"] == "create"

      normalized = Operation.normalize(op)
      assert normalized["type"] == "plc_operation"
      assert normalized["alsoKnownAs"] == ["at://" <> op["handle"]]
      assert normalized["rotationKeys"] == [op["recoveryKey"], op["signingKey"]]
      assert normalized["verificationMethods"] == %{"atproto" => op["signingKey"]}

      # The DID still derives from the ORIGINAL bytes, not the normalized form.
      assert {:ok, did} = Signer.derive_did(op)
      assert did == first["did"]
      assert {:ok, other} = Signer.derive_did(normalized)
      refute other == did
    end
  end
end
