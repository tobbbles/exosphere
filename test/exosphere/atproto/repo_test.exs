defmodule Exosphere.ATProto.RepoTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CAR, CBOR, CID, Crypto, Repo, TestRepoCar}
  alias Exosphere.ATProto.Identity.Document

  defmodule CarHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    # Tests stash the CAR body in the process mailbox via send/2 before
    # calling Repo.verify_checkout/3 (which runs in the same process).
    @impl true
    def get(_url, _opts \\ []) do
      car =
        receive do
          {:car, car} -> car
        after
          0 -> <<>>
        end

      {:ok, %{status: 200, headers: [], body: car}}
    end

    @impl true
    def post(_url, _opts \\ []), do: {:ok, %{status: 200, headers: [], body: %{}}}

    @impl true
    def request(_method, _url, _opts \\ []), do: {:ok, %{status: 200, headers: [], body: %{}}}
  end

  defmodule ErrorHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    @impl true
    def get(_url, _opts \\ []), do: {:ok, %{status: 404, headers: [], body: "nope"}}

    @impl true
    def post(_url, _opts \\ []), do: {:ok, %{status: 404, headers: [], body: "nope"}}

    @impl true
    def request(_method, _url, _opts \\ []), do: {:ok, %{status: 404, headers: [], body: "nope"}}
  end

  # Serves the CAR from the mailbox for getRepo and the DID document from the
  # mailbox for the plc.directory leg DID resolution hits.
  defmodule CarAndDIDHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    @impl true
    def get("https://plc.directory/" <> _did, _opts \\ []) do
      doc =
        receive do
          {:did_doc, doc} -> doc
        after
          0 -> %{}
        end

      {:ok, %{status: 200, headers: [], body: doc}}
    end

    def get(_url, _opts) do
      car =
        receive do
          {:car, car} -> car
        after
          0 -> <<>>
        end

      {:ok, %{status: 200, headers: [], body: car}}
    end

    @impl true
    def post(_url, _opts \\ []), do: {:ok, %{status: 200, headers: [], body: %{}}}

    @impl true
    def request(_method, _url, _opts \\ []), do: {:ok, %{status: 200, headers: [], body: %{}}}
  end

  # Serves the CAR but 404s DID resolution.
  defmodule NoDIDHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    @impl true
    def get("https://plc.directory/" <> _did, _opts \\ []),
      do: {:ok, %{status: 404, headers: [], body: "not found"}}

    def get(_url, _opts) do
      car =
        receive do
          {:car, car} -> car
        after
          0 -> <<>>
        end

      {:ok, %{status: 200, headers: [], body: car}}
    end

    @impl true
    def post(_url, _opts \\ []), do: {:ok, %{status: 200, headers: [], body: %{}}}

    @impl true
    def request(_method, _url, _opts \\ []), do: {:ok, %{status: 200, headers: [], body: %{}}}
  end

  defp did_document(public_key) do
    {:ok, doc} = Document.parse(did_document_map(public_key))
    doc
  end

  # plc.directory-style DID document JSON, as Document.parse/1 expects it.
  defp did_document_map(public_key) do
    {:ok, multibase} = Crypto.to_multibase(public_key, :secp256k1)

    %{
      "id" => "did:plc:44ybard66vv44zksje25o7dz",
      "alsoKnownAs" => ["at://alice.example.com"],
      "verificationMethod" => [
        %{
          "id" => "did:plc:44ybard66vv44zksje25o7dz#atproto",
          "type" => "Multikey",
          "controller" => "did:plc:44ybard66vv44zksje25o7dz",
          "publicKeyMultibase" => multibase
        }
      ]
    }
  end

  describe "verify_checkout/3" do
    test "verifies a full repository CAR against the DID document's key" do
      fixture = TestRepoCar.build()
      send(self(), {:car, fixture.car})

      assert {:ok, result} =
               Repo.verify_checkout("https://pds.example.com", fixture.commit["did"],
                 http: CarHTTP,
                 did_document: did_document(fixture.public_key)
               )

      assert result.records == fixture.records
      assert result.commit == fixture.commit_cid
      assert result.rev == fixture.commit["rev"]
    end

    test "fails signature verification when the commit is signed by another key" do
      fixture = TestRepoCar.build()
      {:ok, %{public_key: other_key}} = Crypto.generate_keypair(:secp256k1)
      send(self(), {:car, fixture.car})

      assert {:error, :invalid_signature} =
               Repo.verify_checkout("https://pds.example.com", fixture.commit["did"],
                 http: CarHTTP,
                 did_document: did_document(other_key)
               )
    end

    test "detects structural tampering of the CAR" do
      fixture = TestRepoCar.build()
      {:ok, %{roots: [root], blocks: blocks}} = CAR.decode_full(fixture.car)
      stripped = Map.drop(blocks, Map.keys(fixture.node_blocks))
      tampered_car = car_bytes(%{roots: [root], blocks: stripped})
      send(self(), {:car, tampered_car})

      assert {:error, {:missing_block, _cid}} =
               Repo.verify_checkout("https://pds.example.com", fixture.commit["did"],
                 http: CarHTTP,
                 verify_signature: false
               )
    end

    test "can skip signature verification" do
      fixture = TestRepoCar.build()
      send(self(), {:car, fixture.car})

      assert {:ok, result} =
               Repo.verify_checkout("https://pds.example.com", fixture.commit["did"],
                 http: CarHTTP,
                 verify_signature: false
               )

      assert result.records == fixture.records
    end

    test "surfaces HTTP errors" do
      assert {:error, {:http_error, 404}} =
               Repo.verify_checkout("https://pds.example.com", "did:plc:x", http: ErrorHTTP)
    end

    test ":http also covers the DID resolution leg" do
      fixture = TestRepoCar.build()
      send(self(), {:car, fixture.car})
      send(self(), {:did_doc, did_document_map(fixture.public_key)})

      # No :did_document opt: the DID must come from CarAndDIDHTTP's
      # plc.directory leg, proving :http is threaded through DID.resolve.
      assert {:ok, result} =
               Repo.verify_checkout("https://pds.example.com", fixture.commit["did"],
                 http: CarAndDIDHTTP
               )

      assert result.records == fixture.records
      assert result.commit == fixture.commit_cid
    end

    test "surfaces DID resolution errors from the :http client" do
      fixture = TestRepoCar.build()
      send(self(), {:car, fixture.car})

      assert {:error, :not_found} =
               Repo.verify_checkout("https://pds.example.com", fixture.commit["did"],
                 http: NoDIDHTTP
               )
    end
  end

  # Re-encode a decoded CAR map back to bytes (header + kept blocks).
  defp car_bytes(%{roots: roots, blocks: blocks}) do
    header_bin = CBOR.encode!(%{"v" => 1, "roots" => roots})

    entries =
      blocks
      |> Enum.map(fn {cid, data} ->
        block_data = if is_binary(data), do: data, else: CBOR.encode!(data)
        entry = CID.to_bytes(cid) <> block_data
        leb128(byte_size(entry)) <> entry
      end)
      |> IO.iodata_to_binary()

    leb128(byte_size(header_bin)) <> header_bin <> entries
  end

  defp leb128(int) when int < 128, do: <<int>>
  defp leb128(int), do: <<1::1, Integer.mod(int, 128)::7, leb128(div(int, 128))::binary>>
end
