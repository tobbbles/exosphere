defmodule Exosphere.ATProto.Spaces.SyncTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CID, Crypto}
  alias Exosphere.ATProto.OAuth.{DPoP, JWK}
  alias Exosphere.ATProto.Spaces.{Commit, Lthash, Repo, Sync, Token}

  @space_host "https://space-host.example.com"
  @repo_host "https://repo-host.example.com"
  @authority "did:plc:spaceauthority"
  @author "did:plc:author"
  @space "at://" <> @authority <> "/space/com.example.group/default"
  @now 1_800_000_000

  defmodule SyncHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    @impl true
    def get(url, opts \\ []) do
      verify_dpop!(opts, "GET", url)
      stage(:get, url)
    end

    @impl true
    def post(url, opts \\ []) do
      verify_dpop!(opts, "POST", url)
      Process.put(:last_post_body, opts[:json])
      stage(:post, url)
    end

    @impl true
    def request(:get, url, opts), do: get(url, opts)
    def request(:post, url, opts), do: post(url, opts)

    # Every request must carry the credential DPoP-bound with a valid proof.
    defp verify_dpop!(opts, htm, url) do
      headers = opts[:headers] || []

      assert {"authorization", "DPoP " <> cred} = List.keyfind(headers, "authorization", 0)
      {"dpop", dpop} = List.keyfind(headers, "dpop", 0)

      assert {:ok, _} = DPoP.verify_proof(dpop, htm, url, credential: cred)
    end

    defp stage(key, url) do
      Process.put(:last_url, url)

      case Process.get(key) do
        nil -> {:ok, %{status: 404, headers: [], body: %{}}}
        response -> response.(url)
      end
    end
  end

  setup do
    {:ok, authority_key} = JWK.generate(:secp256k1)
    {:ok, user_key} = JWK.generate(:secp256k1)
    {:ok, dpop_key} = DPoP.generate_key()
    {:ok, jkt} = JWK.thumbprint(JWK.to_public(dpop_key))

    {:ok, credential} =
      Token.sign(
        :credential,
        [iss: @authority, sub: @space, dpop_jkt: jkt, iat: @now],
        authority_key
      )

    {:ok, %{public_key: pub}} = Crypto.generate_keypair(:secp256k1)

    %{
      authority_key: authority_key,
      user_key: user_key,
      pub: pub,
      cred: %{credential: credential, dpop_key: dpop_key}
    }
  end

  test "list_repo_ops decodes the head commit's bytes", ctx do
    Process.put(:get, fn _url ->
      {:ok,
       %{
         status: 200,
         headers: [],
         body: %{
           "ops" => [],
           "commit" => %{
             "ver" => 1,
             "hash" => Base.url_encode64(<<7::256>>, padding: false),
             "rev" => "head"
           }
         }
       }}
    end)

    assert {:ok, %{commit: %{"hash" => <<7::256>>}}} =
             Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred, http: SyncHTTP)
  end

  test "list_repos returns the writer set with decoded commit hashes", ctx do
    hash = :crypto.hash(:sha256, "state")

    Process.put(
      :get,
      fn url ->
        assert String.contains?(url, "/xrpc/com.atproto.space.listRepos?")
        assert String.contains?(url, "space=" <> URI.encode_www_form(@space))

        {:ok,
         %{
           status: 200,
           headers: [],
           body: %{
             "repos" => [
               %{
                 "did" => @author,
                 "rev" => "3kbcq3p7ad400",
                 "hash" => Base.url_encode64(hash, padding: false)
               }
             ],
             "cursor" => "next"
           }
         }}
      end
    )

    assert {:ok, %{repos: [repo], cursor: "next"}} =
             Sync.list_repos(@space_host, @space, ctx.cred, http: SyncHTTP)

    assert repo == %{did: @author, rev: "3kbcq3p7ad400", hash: hash}

    # limit/cursor reach the wire
    assert {:ok, _} =
             Sync.list_repos(@space_host, @space, ctx.cred,
               http: SyncHTTP,
               limit: 500,
               cursor: "next"
             )

    assert Process.get(:last_url) =~ "limit=500"
    assert Process.get(:last_url) =~ "cursor=next"
  end

  test "list_repo_ops pages ops with the head commit", ctx do
    ops = [
      %{
        "rev" => "3kbcq3p7ad42a",
        "collection" => "c.a",
        "rkey" => "1",
        "cid" => nil,
        "prev" => "bafyrei"
      },
      %{
        "rev" => "3kbcq3p7ad42b",
        "collection" => "c.a",
        "rkey" => "2",
        "cid" => "bafyreib",
        "prev" => nil
      }
    ]

    Process.put(:get, fn url ->
      assert String.contains?(url, "since=3kbcq3p7ad400")

      {:ok,
       %{
         status: 200,
         headers: [],
         body: %{
           "ops" => ops,
           "commit" => %{
             "ver" => 1,
             "hash" => Base.url_encode64(:crypto.hash(:sha256, "head-state"), padding: false),
             "rev" => "head"
           }
         }
       }}
    end)

    assert {:ok, %{ops: ^ops, commit: %{"rev" => "head", "hash" => head_hash}, cursor: nil}} =
             Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               since: "3kbcq3p7ad400"
             )
  end

  test "get_repo verifies a full CAR end to end", ctx do
    commit_ctx = %{space: @space, author: @author}

    records = [
      {"com.example.groupPost", "3jz1", %{"$type" => "com.example.groupPost", "text" => "one"}},
      {"com.example.groupPost", "3jz2", %{"$type" => "com.example.groupPost", "text" => "two"}}
    ]

    hash =
      Enum.reduce(records, Lthash.new(), fn {c, r, rec}, h ->
        Commit.add_record(h, c, r, CID.encode(CID.create!(rec)))
      end)

    # verify_car checks the *author's* #atproto key, so the repo host serves
    # a commit the author signed.
    {:ok, %{public_key: author_pub, private_key: author_priv}} =
      Crypto.generate_keypair(:secp256k1)

    {:ok, commit} =
      Commit.sign(hash, Map.put(commit_ctx, :rev, "3kbcq3p7ad400"), author_priv, :secp256k1)

    car = Repo.serialize(commit, records)

    Process.put(:get, fn _url -> {:ok, %{status: 200, headers: [], body: car}} end)

    assert {:ok, verified} =
             Sync.get_repo(
               @repo_host,
               @space,
               @author,
               commit_ctx,
               author_pub,
               :secp256k1,
               ctx.cred,
               http: SyncHTTP
             )

    assert length(verified.records) == 2
    assert Lthash.digest(verified.lthash) == commit["hash"]
    assert Sync.synced?(verified.lthash, commit["hash"])
  end

  test "the running set hash detects divergence and converges through ops", ctx do
    cid_a = "bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244"
    cid_b = "bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a"

    create = %{
      "rev" => "3kbcq3p7ad42a",
      "collection" => "c.a",
      "rkey" => "1",
      "cid" => cid_a,
      "prev" => nil
    }

    update = %{
      "rev" => "3kbcq3p7ad42b",
      "collection" => "c.a",
      "rkey" => "1",
      "cid" => cid_b,
      "prev" => cid_a
    }

    delete = %{
      "rev" => "3kbcq3p7ad42c",
      "collection" => "c.a",
      "rkey" => "1",
      "cid" => nil,
      "prev" => cid_b
    }

    running =
      Lthash.new()
      |> Sync.apply_ops([create, update, delete])

    assert Lthash.empty?(running)

    running = Lthash.new() |> Sync.apply_ops([create])
    refute Sync.synced?(running, :crypto.hash(:sha256, "not-the-state"))
    assert Sync.synced?(running, Lthash.digest(running))
  end

  test "register_notify posts the subscriber's service identifier", ctx do
    service = "did:web:syncer.example.com#atproto_space_syncer"

    Process.put(:post, fn url ->
      assert String.contains?(url, "/xrpc/com.atproto.space.registerNotify")
      {:ok, %{status: 200, headers: [], body: %{"expiresAt" => "2026-01-01T00:00:00Z"}}}
    end)

    assert {:ok, %{"expiresAt" => _}} =
             Sync.register_notify(@space_host, @space, service, ctx.cred, http: SyncHTTP)

    # The notify registration is a procedure: JSON body {space, service}.
    assert Process.get(:last_post_body) == %{"space" => @space, "service" => service}

    Process.put(:post, fn _url -> {:ok, %{status: 200, headers: [], body: %{}}} end)
    assert :ok = Sync.unregister_notify(@space_host, @space, service, ctx.cred, http: SyncHTTP)
  end

  test "list_records and get_record hit the repo host", ctx do
    Process.put(:get, fn url ->
      assert String.contains?(url, URI.encode_www_form("com.example.groupPost"))
      {:ok, %{status: 200, headers: [], body: %{"records" => []}}}
    end)

    assert {:ok, %{"records" => []}} =
             Sync.list_records(@repo_host, @space, @author, "com.example.groupPost", ctx.cred,
               http: SyncHTTP
             )

    assert {:ok, %{}} =
             Sync.get_record(@repo_host, @space, @author, "com.example.groupPost", "1", ctx.cred,
               http: SyncHTTP
             )
  end
end
