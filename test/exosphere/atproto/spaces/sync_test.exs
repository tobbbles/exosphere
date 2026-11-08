defmodule Exosphere.ATProto.Spaces.SyncTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CID, Crypto}
  alias Exosphere.ATProto.OAuth.JWK

  alias Exosphere.ATProto.Spaces.{
    Commit,
    Credential,
    HttpSignature,
    Kem,
    Lthash,
    Mac,
    Repo,
    Sync,
    Token
  }

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
      verify_presentation!(opts, url)
      Process.put(:last_get_headers, opts[:headers])
      stage(:get, url)
    end

    @impl true
    def post(url, opts \\ []) do
      verify_presentation!(opts, url)
      Process.put(:last_post_body, opts[:json])
      stage(:post, url)
    end

    @impl true
    def request(:get, url, opts), do: get(url, opts)
    def request(:post, url, opts), do: post(url, opts)

    @host_methods ~w(listRepos registerNotify unregisterNotify)

    # Every request must present the credential the way a host verifies it:
    # Atproto-Space-Credential scheme, the right audience (the authority for
    # space-host methods, the repo owner otherwise), and a valid signature by
    # the credential's bound key.
    defp verify_presentation!(opts, url) do
      # As a host derives it: the repo param for repo methods, the authority
      # for space-host methods.
      query = URI.decode_query(URI.parse(url).query || "")

      audience =
        if Enum.any?(@host_methods, &String.contains?(url, "com.atproto.space." <> &1)),
          do: "did:plc:spaceauthority",
          else: query["repo"]

      key = Process.get(:authority_public_jwk)

      assert {:ok, _} =
               Exosphere.ATProto.Spaces.Credential.verify_request(opts[:headers] || [],
                 audience: audience,
                 get_signing_key: fn _, _, _ -> {:ok, key} end,
                 now: 1_800_000_000
               )
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
    {:ok, key} = HttpSignature.generate_key()
    Process.put(:authority_public_jwk, JWK.to_public(authority_key))

    {:ok, credential} =
      Token.sign(
        :credential,
        [iss: @authority, sub: @space, key_id: key.did_key, iat: @now],
        authority_key
      )

    {:ok, %{public_key: pub}} = Crypto.generate_keypair(:secp256k1)

    # The author's #atproto_kem key: the syncer gets the public half, the mock
    # repo host decapsulates with the private half to MAC what it serves.
    {:ok, kem} = Crypto.generate_keypair(:p256)
    Process.put(:kem_private, kem.private_key)

    %{
      kem: kem.public_key,
      authority_key: authority_key,
      user_key: user_key,
      pub: pub,
      cred: %{credential: credential, key: key}
    }
  end

  test "a request is refused by the host check when presented to the wrong audience", ctx do
    {:ok, headers} = Credential.presentation_headers(ctx.cred, @author)

    assert {:error, :bad_audience} =
             Credential.verify_request(headers,
               audience: @authority,
               get_signing_key: fn _, _, _ -> {:ok, JWK.to_public(ctx.authority_key)} end,
               now: @now
             )
  end

  # The lexicon `bytes` wire form, exactly as a conforming host emits it: the
  # $bytes wrapper over standard-alphabet base64 with padding. The old doubles
  # encoded bare url-safe strings — what the client believed, not what the
  # data model specifies — which is how the decoding bug survived them.
  defp bytes(bin), do: %{"$bytes" => Base.encode64(bin)}

  # What a conforming repo host answers with: the MAC under the shared secret
  # it decapsulates from the request's Atproto-Space-Want-Mac key share.
  defp host_mac(type, subject) do
    {_, want} = List.keyfind(Process.get(:last_get_headers), "atproto-space-want-mac", 0)
    {:ok, key_share} = Mac.parse_want_mac_header(want, type)
    {:ok, secret} = Kem.decapsulate(Process.get(:kem_private), key_share)

    mac =
      case {type, subject} do
        {:commit, commit} -> Mac.commit_mac(secret, commit)
        {:record, {uri, cid}} -> Mac.record_mac(secret, uri, CID.to_bytes(cid))
      end

    {"atproto-space-mac", Mac.mac_header(type, mac)}
  end

  defp head_commit(data \\ :crypto.hash(:sha256, "head-state")) do
    %{"ver" => 1, "repo" => @author, "space" => @space, "rev" => "3kbcq3p7ad42b", "data" => data}
  end

  defp wire(commit), do: Map.put(commit, "data", bytes(commit["data"]))

  test "SinceOutOfBounds is typed, with the floor parsed from the message", ctx do
    # The wire shape a host emits when `since` predates (or falls outside) the
    # retained oplog window — the cue to recover via the full CAR.
    Process.put(:get, fn _url ->
      {:ok,
       %{
         status: 400,
         headers: [],
         body: %{
           "error" => "SinceOutOfBounds",
           "message" =>
             "since predates the retained oplog window; the oldest retained rev is 3kbcq3p7ad2c2 — recover with a full getRepo"
         }
       }}
    end)

    assert {:error, {:since_out_of_bounds, "3kbcq3p7ad2c2"}} =
             Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem,
               since: "3kbcq3p7ad400"
             )

    # A host that words the refusal differently still gets the typed error,
    # just without a floor (the message is prose, not a lexicon field).
    Process.put(:get, fn _url ->
      {:ok,
       %{
         status: 400,
         headers: [],
         body: %{"error" => "SinceOutOfBounds", "message" => "no ops are retained"}
       }}
    end)

    assert {:error, {:since_out_of_bounds, nil}} =
             Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )

    # Anything that merely looks like a floor is not one: the candidate must
    # be a valid TID.
    Process.put(:get, fn _url ->
      {:ok,
       %{
         status: 400,
         headers: [],
         body: %{
           "error" => "SinceOutOfBounds",
           "message" => "oldest retained rev is notarealtid0"
         }
       }}
    end)

    assert {:error, {:since_out_of_bounds, nil}} =
             Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )
  end

  test "account-state refusals are typed, for the writer set and repo reads", ctx do
    for {code, expected} <- [
          {"RepoTakendown", :repo_takendown},
          {"RepoDeactivated", :repo_deactivated},
          {"RepoSuspended", :repo_suspended}
        ] do
      Process.put(:get, fn _url ->
        {:ok, %{status: 400, headers: [], body: %{"error" => code, "message" => "..."}}}
      end)

      assert {:error, ^expected} = Sync.list_repos(@space_host, @space, ctx.cred, http: SyncHTTP)

      assert {:error, ^expected} =
               Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred,
                 http: SyncHTTP,
                 kem_key: ctx.kem
               )
    end
  end

  test "other 400s keep the generic http_error shape", ctx do
    Process.put(:get, fn _url ->
      {:ok, %{status: 400, headers: [], body: %{"error" => "SpaceNotFound", "message" => "..."}}}
    end)

    assert {:error, {:http_error, 400}} =
             Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )

    # And a body-less 400 (e.g. a proxy) stays generic too.
    Process.put(:get, fn _url -> {:ok, %{status: 400, headers: [], body: ""}} end)

    assert {:error, {:http_error, 400}} =
             Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )
  end

  test "list_repo_ops verifies the head commit against the response MAC", ctx do
    commit = head_commit()

    Process.put(:get, fn _url ->
      {:ok,
       %{
         status: 200,
         headers: [host_mac(:commit, commit)],
         body: %{"ops" => [], "commit" => wire(commit)}
       }}
    end)

    assert {:ok, %{commit: ^commit}} =
             Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )

    # The request asked for the commit MAC with a fresh did:key share.
    {_, want} = List.keyfind(Process.get(:last_get_headers), "atproto-space-want-mac", 0)
    assert want =~ ~s(type="atproto-space-repo", ver=1, key_share="did:key:zDn)

    # A head commit without a MAC header is refused; so is a wrong MAC.
    Process.put(:get, fn _url ->
      {:ok, %{status: 200, headers: [], body: %{"ops" => [], "commit" => wire(commit)}}}
    end)

    assert {:error, {:bad_space_mac, :missing_header}} =
             Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )

    Process.put(:get, fn _url ->
      forged = {"atproto-space-mac", Mac.mac_header(:commit, :binary.copy(<<0>>, 32))}
      {:ok, %{status: 200, headers: [forged], body: %{"ops" => [], "commit" => wire(commit)}}}
    end)

    assert {:error, :invalid_mac} =
             Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )

    # A backfill page (no commit) carries no MAC and needs none.
    Process.put(:get, fn _url ->
      {:ok, %{status: 200, headers: [], body: %{"ops" => [], "cursor" => "c"}}}
    end)

    assert {:ok, %{commit: nil, cursor: "c"}} =
             Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )
  end

  test "MAC'd methods need the author's KEM key", ctx do
    assert {:error, :missing_kem_key} =
             Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred, http: SyncHTTP)

    assert {:error, :missing_kem_key} =
             Sync.get_repo(@repo_host, @space, @author, ctx.cred, http: SyncHTTP)
  end

  test "bytes use the standard alphabet, padding optional, url-safe rejected", ctx do
    # Encodes to "Fb7+/w0=" — `+`, `/` and `=` are legal in the data model's
    # base64 and illegal in base64url.
    hash = <<21, 190, 254, 255, 13>>
    unpadded = %{"$bytes" => String.trim_trailing(Base.encode64(hash), "=")}

    for wire <- [bytes(hash), unpadded] do
      Process.put(:get, fn _url ->
        {:ok,
         %{
           status: 200,
           headers: [],
           body: %{
             "repos" => [%{"did" => @author, "repoRev" => "r", "spaceRev" => "s", "data" => wire}]
           }
         }}
      end)

      assert {:ok, %{repos: [%{data: ^hash}]}} =
               Sync.list_repos(@space_host, @space, ctx.cred, http: SyncHTTP, kem_key: ctx.kem)
    end

    # The same bytes in the url-safe alphabet are not the data model's base64.
    urlsafe = Base.url_encode64(hash)

    Process.put(:get, fn _url ->
      {:ok,
       %{
         status: 200,
         headers: [],
         body: %{
           "repos" => [
             %{
               "did" => @author,
               "repoRev" => "r",
               "spaceRev" => "s",
               "data" => %{"$bytes" => urlsafe}
             }
           ]
         }
       }}
    end)

    assert {:error, {:invalid_bytes, "data"}} =
             Sync.list_repos(@space_host, @space, ctx.cred, http: SyncHTTP, kem_key: ctx.kem)
  end

  test "malformed bytes are an error, not a silent pass-through", ctx do
    Process.put(:get, fn _url ->
      {:ok,
       %{
         status: 200,
         headers: [],
         body: %{
           "ops" => [],
           "commit" => %{head_commit() | "data" => %{"$bytes" => "not*base64!"}}
         }
       }}
    end)

    assert {:error, {:invalid_bytes, "data"}} =
             Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )
  end

  test "get_latest_commit returns the MAC-verified commit", ctx do
    commit = head_commit()

    Process.put(:get, fn url ->
      assert String.contains?(url, "/xrpc/com.atproto.space.getLatestCommit?")

      {:ok,
       %{status: 200, headers: [host_mac(:commit, commit)], body: %{"commit" => wire(commit)}}}
    end)

    assert {:ok, ^commit} =
             Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )

    # A commit for another repo is refused even with a valid MAC over it.
    other = %{commit | "repo" => "did:plc:someoneelse"}

    Process.put(:get, fn _url ->
      {:ok, %{status: 200, headers: [host_mac(:commit, other)], body: %{"commit" => wire(other)}}}
    end)

    assert {:error, :repo_mismatch} =
             Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )
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
                 "repoRev" => "3kbcq3p7ad400",
                 "spaceRev" => "3kbcq3p7ad4zz",
                 "data" => bytes(hash)
               }
             ],
             "cursor" => "3kbcq3p7ad4zz"
           }
         }}
      end
    )

    assert {:ok, %{repos: [repo], cursor: "3kbcq3p7ad4zz"}} =
             Sync.list_repos(@space_host, @space, ctx.cred, http: SyncHTTP, kem_key: ctx.kem)

    # The repo's own revision and the host's sequence position are separate
    # fields with separate jobs (see `list_repos/4`), and neither is read as
    # the other.
    assert repo == %{
             did: @author,
             repo_rev: "3kbcq3p7ad400",
             space_rev: "3kbcq3p7ad4zz",
             data: hash
           }

    # limit/cursor reach the wire
    assert {:ok, _} =
             Sync.list_repos(@space_host, @space, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem,
               limit: 500,
               cursor: "next"
             )

    assert Process.get(:last_url) =~ "limit=500"
    assert Process.get(:last_url) =~ "cursor=next"
  end

  test "list_repos does not read a pre-rename host's `rev`/`hash` as `repoRev`/`data`", ctx do
    # A host on the lexicon before atproto 357c4cee9 still says `rev`, and one
    # before 5791385 still says `hash`. The client answers "unknown" rather than
    # guessing the old field means the new one — `nil` is a value every caller
    # already handles, a wrong guess is not.
    Process.put(:get, fn _url ->
      {:ok,
       %{
         status: 200,
         headers: [],
         body: %{"repos" => [%{"did" => @author, "rev" => "3kbcq3p7ad400", "hash" => bytes("h")}]}
       }}
    end)

    assert {:ok, %{repos: [%{repo_rev: nil, space_rev: nil, data: nil}], cursor: nil}} =
             Sync.list_repos(@space_host, @space, ctx.cred, http: SyncHTTP, kem_key: ctx.kem)
  end

  test "decode_notify_write/1 shapes a forwarded notification" do
    data = :crypto.hash(:sha256, "state")

    assert {:ok,
            %{
              space: @space,
              repo: @author,
              repo_rev: "3kbcq3p7ad400",
              data: ^data,
              space_rev: "3kbcq3p7ad4zz",
              prev_space_rev: "3kbcq3p7ad4yy"
            }} =
             Sync.decode_notify_write(%{
               "space" => @space,
               "repo" => @author,
               "repoRev" => "3kbcq3p7ad400",
               "data" => bytes(data),
               "spaceRev" => "3kbcq3p7ad4zz",
               "prevSpaceRev" => "3kbcq3p7ad4yy"
             })

    # A pre-5791385 body (`hash`, no `data`) is missing a required field.
    assert {:error, {:missing_field, "data"}} =
             Sync.decode_notify_write(%{
               "space" => @space,
               "repo" => @author,
               "repoRev" => "3kbcq3p7ad400",
               "hash" => bytes(data)
             })
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

    commit = head_commit()

    Process.put(:get, fn url ->
      assert String.contains?(url, "since=3kbcq3p7ad400")
      assert String.contains?(url, "excludeValues=true")

      {:ok,
       %{
         status: 200,
         headers: [host_mac(:commit, commit)],
         body: %{"ops" => ops, "commit" => wire(commit)}
       }}
    end)

    assert {:ok, %{ops: ^ops, commit: ^commit, cursor: nil}} =
             Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem,
               since: "3kbcq3p7ad400",
               exclude_values: true
             )
  end

  test "get_repo verifies a full STAR archive end to end", ctx do
    records = [
      {"com.example.groupPost", "3jz1", %{"$type" => "com.example.groupPost", "text" => "one"}},
      {"com.example.groupPost", "3jz2", %{"$type" => "com.example.groupPost", "text" => "two"}}
    ]

    hash =
      Enum.reduce(records, Lthash.new(), fn {c, r, rec}, h ->
        Commit.add_record(h, c, r, CID.encode(CID.create!(rec)))
      end)

    commit = Commit.build(hash, %{space: @space, repo: @author, rev: "3kbcq3p7ad400"})
    star = Repo.serialize(commit, records)

    Process.put(:get, fn url ->
      assert String.contains?(url, "/xrpc/com.atproto.space.getRepo?")
      {:ok, %{status: 200, headers: [host_mac(:commit, commit)], body: star}}
    end)

    assert {:ok, verified} =
             Sync.get_repo(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )

    assert length(verified.records) == 2
    assert Sync.synced?(verified.lthash, commit)
    assert Sync.synced?(verified.lthash, commit["data"])

    # Served for a different repo than asked: refused.
    assert {:error, :repo_mismatch} =
             Sync.get_repo(@repo_host, @space, "did:plc:other", ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )
  end

  test "the running set hash detects divergence and converges through ops" do
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
             Sync.register_notify(@space_host, @space, service, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )

    # The notify registration is a procedure: JSON body {space, service}.
    assert Process.get(:last_post_body) == %{"space" => @space, "service" => service}

    Process.put(:post, fn _url -> {:ok, %{status: 200, headers: [], body: %{}}} end)

    assert :ok =
             Sync.unregister_notify(@space_host, @space, service, ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )
  end

  test "list_records lists across collections, with excludeValues", ctx do
    Process.put(:get, fn url ->
      assert String.contains?(url, "/xrpc/com.atproto.space.listRecords?")
      assert String.contains?(url, "excludeValues=true")
      refute String.contains?(url, "collection=")
      {:ok, %{status: 200, headers: [], body: %{"records" => []}}}
    end)

    assert {:ok, %{"records" => []}} =
             Sync.list_records(@repo_host, @space, @author, ctx.cred,
               http: SyncHTTP,
               exclude_values: true
             )
  end

  test "get_record verifies the record MAC, the URI, and the value's CID", ctx do
    value = %{"$type" => "com.example.groupPost", "text" => "one"}
    cid = CID.create!(value)
    uri = @space <> "/" <> @author <> "/com.example.groupPost/3jz1"

    body = %{"uri" => uri, "cid" => CID.encode(cid), "value" => value}

    Process.put(:get, fn _url ->
      {:ok, %{status: 200, headers: [host_mac(:record, {uri, cid})], body: body}}
    end)

    assert {:ok, ^body} =
             Sync.get_record(
               @repo_host,
               @space,
               @author,
               "com.example.groupPost",
               "3jz1",
               ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )

    {_, want} = List.keyfind(Process.get(:last_get_headers), "atproto-space-want-mac", 0)
    assert want =~ ~s(type="atproto-space-record", ver=1)

    # A value that does not encode to the MAC'd CID is refused.
    Process.put(:get, fn _url ->
      {:ok,
       %{
         status: 200,
         headers: [host_mac(:record, {uri, cid})],
         body: %{body | "value" => %{"text" => "two"}}
       }}
    end)

    assert {:error, :record_cid_mismatch} =
             Sync.get_record(
               @repo_host,
               @space,
               @author,
               "com.example.groupPost",
               "3jz1",
               ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )

    # A record other than the one requested is refused.
    assert {:error, :record_uri_mismatch} =
             Sync.get_record(
               @repo_host,
               @space,
               @author,
               "com.example.groupPost",
               "3jz9",
               ctx.cred,
               http: SyncHTTP,
               kem_key: ctx.kem
             )
  end
end
