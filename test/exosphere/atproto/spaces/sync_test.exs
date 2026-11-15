defmodule Exosphere.ATProto.Spaces.SyncTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CID, Crypto}
  alias Exosphere.ATProto.OAuth.JWK

  alias Exosphere.ATProto.Spaces.{
    Commit,
    Credential,
    HttpSignature,
    Lthash,
    Mac,
    Repo,
    Sync,
    Token
  }

  @space_host "https://space-host.example.com"
  @repo_host "https://repo-host.example.com"
  @syncer "https://syncer.example.com"
  @authority "did:plc:spaceauthority"
  @author "did:plc:author"
  @space "at://" <> @authority <> "/space/com.example.group/default"
  @now 1_800_000_000

  defmodule SyncHTTP do
    @behaviour Exosphere.ATProto.HTTP.Behaviour

    alias Exosphere.ATProto.Spaces.Credential
    alias Exosphere.ATProto.XRPC.ServiceAuth

    @impl true
    def get(url, opts \\ []) do
      verify_presentation!(opts, url)
      Process.put(:last_get_headers, opts[:headers])
      Process.put(:get_count, Process.get(:get_count, 0) + 1)
      stage(:get, url)
    end

    @impl true
    def post(url, opts \\ []) do
      if String.contains?(url, "com.atproto.space.notifyRepoUpdate"),
        do: verify_service_auth!(opts),
        else: refute_auth!(opts)

      Process.put(:last_post_headers, opts[:headers])
      Process.put(:last_post_body, opts[:json])
      stage(:post, url)
    end

    @impl true
    def request(:get, url, opts), do: get(url, opts)
    def request(:post, url, opts), do: post(url, opts)

    # notifyRepoUpdate carries service auth from the repo's account, checked
    # the way the reference space host does: signature by the repo's key,
    # `iss` the repo, `aud` the authority's space host, `lxm` the method.
    defp verify_service_auth!(opts) do
      {_, "Bearer " <> jwt} =
        Enum.find(opts[:headers], fn {k, _} -> String.downcase(k) == "authorization" end)

      key = Process.get(:repo_public_jwk)

      assert {:ok, payload} =
               ServiceAuth.verify(jwt, fn _, _, _ -> {:ok, key} end,
                 aud: ["did:plc:spaceauthority", "did:plc:spaceauthority#atproto_pds"],
                 lxm: "com.atproto.space.notifyRepoUpdate"
               )

      Process.put(:last_service_auth, payload)
    end

    # confirmRegistration and notifySpaceUpdate carry no auth: the token in
    # the body is what authenticates them.
    defp refute_auth!(opts) do
      refute Enum.any?(opts[:headers] || [], fn {k, _} ->
               String.downcase(k) in ["authorization", "atproto-space-audience"]
             end)
    end

    # Every read must present the credential the way a host verifies it:
    # Atproto-Space-Credential scheme, the right audience (the authority for
    # listWriters, the repo owner otherwise), and a valid signature by the
    # credential's bound key.
    defp verify_presentation!(opts, url) do
      query = URI.decode_query(URI.parse(url).query || "")

      audience =
        if String.contains?(url, "com.atproto.space.listWriters"),
          do: "did:plc:spaceauthority",
          else: query["repo"]

      key = Process.get(:authority_public_jwk)

      assert {:ok, _} =
               Credential.verify_request(opts[:headers] || [],
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
    {:ok, key} = HttpSignature.generate_key()
    Process.put(:authority_public_jwk, JWK.to_public(authority_key))

    {:ok, credential} =
      Token.sign(
        :credential,
        [iss: @authority, sub: @space, key_id: key.did_key, iat: @now],
        authority_key
      )

    # The author's #atproto_kem key: the syncer gets the public half, the mock
    # repo host decapsulates with the private half to MAC what it serves.
    {:ok, kem} = Crypto.generate_keypair(:p256)
    Process.put(:kem_private, kem.private_key)

    %{
      kem: kem.public_key,
      authority_key: authority_key,
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

  # The lexicon `bytes` wire form as a conforming host emits it: the $bytes
  # wrapper over standard-alphabet base64.
  defp bytes(bin), do: %{"$bytes" => Base.encode64(bin)}

  # What a conforming repo host answers with: it finds the MAC requested for
  # the profile in Accept-Signature, decapsulates the key share with the
  # author's KEM private key, and signs a header describing what it returns.
  defp host_mac(profile, subject) do
    {_, accept} = List.keyfind(Process.get(:last_get_headers), "accept-signature", 0)
    {:ok, request} = Mac.parse_request(accept, profile)
    {:ok, params} = Mac.decapsulate(request, Process.get(:kem_private))

    case {profile, subject} do
      {:commit, commit} -> Mac.commit_headers(commit, params)
      {:record, {uri, cid}} -> Mac.record_headers(uri, cid, params)
    end
  end

  defp head_commit(data \\ :crypto.hash(:sha256, "head-state")) do
    %{"ver" => 1, "repo" => @author, "space" => @space, "rev" => "3kbcq3p7ad42b", "data" => data}
  end

  defp wire(commit), do: Map.put(commit, "data", bytes(commit["data"]))

  defp keyid do
    {_, accept} = List.keyfind(Process.get(:last_get_headers), "accept-signature", 0)
    [_, keyid] = Regex.run(~r/keyid="([^"]+)"/, accept)
    keyid
  end

  describe "errors" do
    test "SinceOutOfBounds is typed, with the floor parsed from the message", ctx do
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
                 since: "3kbcq3p7ad42a"
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

      # Anything that merely looks like a floor is not one: it must be a TID.
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

        assert {:error, ^expected} =
                 Sync.list_writers(@space_host, @space, ctx.cred, http: SyncHTTP)

        assert {:error, ^expected} =
                 Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred,
                   http: SyncHTTP,
                   kem_key: ctx.kem
                 )
      end
    end

    test "RepoNotFound is typed: a never-written (or collected) repo", ctx do
      Process.put(:get, fn _url ->
        {:ok, %{status: 400, headers: [], body: %{"error" => "RepoNotFound"}}}
      end)

      opts = [http: SyncHTTP, kem_key: ctx.kem]

      assert {:error, :repo_not_found} =
               Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred, opts)

      assert {:error, :repo_not_found} =
               Sync.get_repo(@repo_host, @space, @author, ctx.cred, opts)

      assert {:error, :repo_not_found} =
               Sync.sync_repo(
                 @repo_host,
                 @space,
                 @author,
                 ctx.cred,
                 %{rev: "3kbcq3p7ad42a", lthash: Lthash.new()},
                 opts
               )
    end

    test "other 400s keep the generic http_error shape", ctx do
      Process.put(:get, fn _url ->
        {:ok,
         %{status: 400, headers: [], body: %{"error" => "SpaceNotFound", "message" => "..."}}}
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

    test "the November 12 error names are typed, the old ones are not", ctx do
      for {code, expected} <- [
            {"InvalidSpaceMac", :invalid_space_mac},
            {"InvalidCursor", :invalid_cursor}
          ] do
        Process.put(:get, fn _url ->
          {:ok, %{status: 400, headers: [], body: %{"error" => code, "message" => "..."}}}
        end)

        assert {:error, ^expected} =
                 Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred,
                   http: SyncHTTP,
                   kem_key: ctx.kem
                 )

        assert {:error, ^expected} =
                 Sync.list_records(@repo_host, @space, @author, ctx.cred, http: SyncHTTP)
      end

      Process.put(:get, fn _url ->
        {:ok, %{status: 400, headers: [], body: %{"error" => "BadSpaceMac"}}}
      end)

      assert {:error, {:http_error, 400}} =
               Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred,
                 http: SyncHTTP,
                 kem_key: ctx.kem
               )
    end

    test "MAC'd methods need the author's KEM key", ctx do
      assert {:error, :missing_kem_key} =
               Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred, http: SyncHTTP)

      assert {:error, :missing_kem_key} =
               Sync.get_repo(@repo_host, @space, @author, ctx.cred, http: SyncHTTP)

      assert {:error, :missing_kem_key} =
               Sync.get_record(@repo_host, @space, @author, "a.b.c", "x", ctx.cred,
                 http: SyncHTTP
               )
    end
  end

  describe "MACs" do
    test "get_latest_commit asks for the commit profile and verifies the MAC", ctx do
      commit = head_commit()

      Process.put(:get, fn url ->
        assert String.contains?(url, "/xrpc/com.atproto.space.getLatestCommit?")

        {:ok,
         %{status: 200, headers: host_mac(:commit, commit), body: %{"commit" => wire(commit)}}}
      end)

      assert {:ok, ^commit} =
               Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred,
                 http: SyncHTTP,
                 kem_key: ctx.kem
               )

      # The request asked for the commit MAC under the syncer's label, with a
      # fresh did:key share as keyid.
      {_, accept} = List.keyfind(Process.get(:last_get_headers), "accept-signature", 0)

      assert accept =~
               ~r/^mac=\("atproto-space-commit";sf\);keyid="did:key:zDn[^"]+";tag="atproto-space-commit"$/

      # No Atproto-Space-Want-Mac any more.
      refute List.keyfind(Process.get(:last_get_headers), "atproto-space-want-mac", 0)
    end

    test "a commit other than the one requested is refused, even with a valid MAC", ctx do
      other = %{head_commit() | "repo" => "did:plc:someoneelse"}

      Process.put(:get, fn _url ->
        {:ok, %{status: 200, headers: host_mac(:commit, other), body: %{"commit" => wire(other)}}}
      end)

      assert {:error, :repo_mismatch} =
               Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred,
                 http: SyncHTTP,
                 kem_key: ctx.kem
               )
    end

    test "a missing, forged or mismatched MAC is InvalidSpaceMac", ctx do
      commit = head_commit()
      opts = [http: SyncHTTP, kem_key: ctx.kem]

      Process.put(:get, fn _url ->
        {:ok, %{status: 200, headers: [], body: %{"commit" => wire(commit)}}}
      end)

      assert {:error, {:invalid_space_mac, :missing_http_signature}} =
               Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred, opts)

      # A MAC under another secret.
      Process.put(:get, fn _url ->
        {:ok, request} = Mac.parse_request(Mac.format_request(:commit, keyid()), :commit)
        params = Map.put(request, :shared_secret, :binary.copy(<<0>>, 32))

        {:ok,
         %{
           status: 200,
           headers: Mac.commit_headers(commit, params),
           body: %{"commit" => wire(commit)}
         }}
      end)

      assert {:error, {:invalid_space_mac, :mac_mismatch}} =
               Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred, opts)

      # A valid MAC over a header describing a different commit.
      Process.put(:get, fn _url ->
        headers = host_mac(:commit, head_commit(:crypto.hash(:sha256, "other")))
        {:ok, %{status: 200, headers: headers, body: %{"commit" => wire(commit)}}}
      end)

      assert {:error, {:invalid_space_mac, :commit_mismatch}} =
               Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred, opts)
    end

    test "every request derives a fresh key share", ctx do
      commit = head_commit()

      Process.put(:get, fn _url ->
        {:ok,
         %{status: 200, headers: host_mac(:commit, commit), body: %{"commit" => wire(commit)}}}
      end)

      opts = [http: SyncHTTP, kem_key: ctx.kem]
      assert {:ok, _} = Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred, opts)
      first = keyid()
      assert {:ok, _} = Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred, opts)
      refute keyid() == first
    end

    test "a failed verification re-resolves the KEM key and retries once", ctx do
      commit = head_commit()
      {:ok, stale} = Crypto.generate_keypair(:p256)

      Process.put(:get, fn _url ->
        {:ok,
         %{status: 200, headers: host_mac(:commit, commit), body: %{"commit" => wire(commit)}}}
      end)

      # The cached key is stale (rotated); the refreshed one is current.
      resolve = fn refresh? ->
        send(self(), {:resolved, refresh?})
        {:ok, if(refresh?, do: ctx.kem, else: stale.public_key)}
      end

      assert {:ok, ^commit} =
               Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred,
                 http: SyncHTTP,
                 kem_key: resolve
               )

      assert_received {:resolved, false}
      assert_received {:resolved, true}
      assert Process.get(:get_count) == 2

      # A plain key is not retried: the failure is the caller's to handle.
      Process.put(:get_count, 0)

      assert {:error, {:invalid_space_mac, :mac_mismatch}} =
               Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred,
                 http: SyncHTTP,
                 kem_key: stale.public_key
               )

      assert Process.get(:get_count) == 1

      # Nor is a failure that is not a verification failure.
      Process.put(:get_count, 0)

      Process.put(:get, fn _url ->
        {:ok, %{status: 400, headers: [], body: %{"error" => "RepoNotFound"}}}
      end)

      assert {:error, :repo_not_found} =
               Sync.get_latest_commit(@repo_host, @space, @author, ctx.cred,
                 http: SyncHTTP,
                 kem_key: resolve
               )

      assert Process.get(:get_count) == 1
    end
  end

  describe "the writer set" do
    test "list_writers returns typed repoWrite and repoRemoved entries", ctx do
      hash = :crypto.hash(:sha256, "state")

      Process.put(:get, fn url ->
        assert String.contains?(url, "/xrpc/com.atproto.space.listWriters?")
        assert String.contains?(url, "space=" <> URI.encode_www_form(@space))

        {:ok,
         %{
           status: 200,
           headers: [],
           body: %{
             "repos" => [
               %{
                 "$type" => "com.atproto.space.defs#repoWrite",
                 "repo" => @author,
                 "repoRev" => "3kbcq3p7ad42a",
                 "spaceRev" => "3kbcq3p7ad43a",
                 "data" => bytes(hash)
               },
               %{
                 "$type" => "com.atproto.space.defs#repoRemoved",
                 "repo" => "did:plc:gone",
                 "spaceRev" => "3kbcq3p7ad4zz"
               }
             ],
             "cursor" => "3kbcq3p7ad4zz"
           }
         }}
      end)

      assert {:ok, %{repos: [write, removed], cursor: "3kbcq3p7ad4zz"}} =
               Sync.list_writers(@space_host, @space, ctx.cred, http: SyncHTTP)

      assert write == %{
               type: :repo_write,
               repo: @author,
               repo_rev: "3kbcq3p7ad42a",
               space_rev: "3kbcq3p7ad43a",
               data: hash
             }

      assert removed == %{type: :repo_removed, repo: "did:plc:gone", space_rev: "3kbcq3p7ad4zz"}

      # limit/cursor reach the wire
      assert {:ok, _} =
               Sync.list_writers(@space_host, @space, ctx.cred,
                 http: SyncHTTP,
                 limit: 500,
                 cursor: "3kbcq3p7ad43a"
               )

      assert Process.get(:last_url) =~ "limit=500"
      assert Process.get(:last_url) =~ "cursor=3kbcq3p7ad43a"
    end

    test "unknown entry types are skipped; untyped or malformed entries are refused", ctx do
      stage_repos = fn repos ->
        Process.put(:get, fn _url ->
          {:ok, %{status: 200, headers: [], body: %{"repos" => repos}}}
        end)
      end

      stage_repos.([
        %{"$type" => "com.example.future#entry", "repo" => @author},
        %{
          "$type" => "com.atproto.space.defs#repoRemoved",
          "repo" => @author,
          "spaceRev" => "3kbcq3p7ad43a"
        }
      ])

      assert {:ok, %{repos: [%{type: :repo_removed}], cursor: nil}} =
               Sync.list_writers(@space_host, @space, ctx.cred, http: SyncHTTP)

      # A November 5 entry: no $type. Not read across.
      stage_repos.([
        %{
          "repo" => @author,
          "repoRev" => "3kbcq3p7ad42a",
          "spaceRev" => "3kbcq3p7ad43a",
          "data" => bytes("h")
        }
      ])

      assert {:error, :invalid_writer} =
               Sync.list_writers(@space_host, @space, ctx.cred, http: SyncHTTP)

      # A repoWrite missing its data, or with a revision that is not a TID.
      stage_repos.([
        %{
          "$type" => "com.atproto.space.defs#repoWrite",
          "repo" => @author,
          "repoRev" => "3kbcq3p7ad42a",
          "spaceRev" => "3kbcq3p7ad43a"
        }
      ])

      assert {:error, :invalid_writer} =
               Sync.list_writers(@space_host, @space, ctx.cred, http: SyncHTTP)

      stage_repos.([
        %{
          "$type" => "com.atproto.space.defs#repoRemoved",
          "repo" => @author,
          "spaceRev" => "s"
        }
      ])

      assert {:error, :invalid_writer} =
               Sync.list_writers(@space_host, @space, ctx.cred, http: SyncHTTP)
    end

    test "bytes use the standard alphabet, padding optional, url-safe rejected", ctx do
      # Encodes to "Fb7+/w0=" — `+`, `/` and `=` are legal in the data model's
      # base64 and illegal in base64url.
      hash = <<21, 190, 254, 255, 13>>
      unpadded = %{"$bytes" => String.trim_trailing(Base.encode64(hash), "=")}

      entry = fn data ->
        %{
          "$type" => "com.atproto.space.defs#repoWrite",
          "repo" => @author,
          "repoRev" => "3kbcq3p7ad42a",
          "spaceRev" => "3kbcq3p7ad43a",
          "data" => data
        }
      end

      for wire <- [bytes(hash), unpadded] do
        Process.put(:get, fn _url ->
          {:ok, %{status: 200, headers: [], body: %{"repos" => [entry.(wire)]}}}
        end)

        assert {:ok, %{repos: [%{data: ^hash}]}} =
                 Sync.list_writers(@space_host, @space, ctx.cred, http: SyncHTTP)
      end

      Process.put(:get, fn _url ->
        {:ok,
         %{
           status: 200,
           headers: [],
           body: %{"repos" => [entry.(%{"$bytes" => Base.url_encode64(hash)})]}
         }}
      end)

      assert {:error, {:invalid_bytes, "data"}} =
               Sync.list_writers(@space_host, @space, ctx.cred, http: SyncHTTP)
    end

    test "encode_writer/1 and list_writers_output/1 serve a listing" do
      data = :crypto.hash(:sha256, "state")

      writers = [
        %{
          type: :repo_write,
          repo: @author,
          repo_rev: "3kbcq3p7ad42a",
          data: data,
          space_rev: "3kbcq3p7ad43a",
          prev_space_rev: "3kbcq3p7ad42c"
        },
        %{type: :repo_removed, repo: "did:plc:gone", space_rev: "3kbcq3p7ad44a"}
      ]

      assert Sync.list_writers_output(writers) == %{
               "repos" => [
                 # A listing carries no prevSpaceRev.
                 %{
                   "$type" => "com.atproto.space.defs#repoWrite",
                   "repo" => @author,
                   "repoRev" => "3kbcq3p7ad42a",
                   "data" => %{"$bytes" => Base.encode64(data, padding: false)},
                   "spaceRev" => "3kbcq3p7ad43a"
                 },
                 %{
                   "$type" => "com.atproto.space.defs#repoRemoved",
                   "repo" => "did:plc:gone",
                   "spaceRev" => "3kbcq3p7ad44a"
                 }
               ],
               "cursor" => "3kbcq3p7ad44a"
             }

      # An empty page carries no cursor: the end of the walk.
      assert Sync.list_writers_output([]) == %{"repos" => []}
    end
  end

  describe "the oplog" do
    test "list_repo_ops verifies the commit on every page", ctx do
      commit = head_commit()

      ops = [
        %{
          "rev" => "3kbcq3p7ad42a",
          "collection" => "c.a",
          "rkey" => "1",
          "cid" => nil,
          "prev" => "bafyrei"
        }
      ]

      Process.put(:get, fn url ->
        assert String.contains?(url, "since=3kbcq3p7ad42a")
        assert String.contains?(url, "excludeValues=true")

        {:ok,
         %{
           status: 200,
           headers: host_mac(:commit, commit),
           body: %{"ops" => ops, "commit" => wire(commit), "cursor" => "c1"}
         }}
      end)

      # A full page, with a cursor, still carries (and verifies) the commit.
      assert {:ok, %{ops: ^ops, commit: ^commit, cursor: "c1"}} =
               Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred,
                 http: SyncHTTP,
                 kem_key: ctx.kem,
                 since: "3kbcq3p7ad42a",
                 exclude_values: true
               )

      # A page without a commit is refused: the lexicon requires one.
      Process.put(:get, fn _url ->
        {:ok, %{status: 200, headers: [], body: %{"ops" => [], "cursor" => "c"}}}
      end)

      assert {:error, :missing_commit} =
               Sync.list_repo_ops(@repo_host, @space, @author, ctx.cred,
                 http: SyncHTTP,
                 kem_key: ctx.kem
               )
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

    test "sync_repo applies pages until there is no cursor, then checks the commit", ctx do
      cid_a = CID.encode(CID.create!(%{"text" => "a"}))
      cid_b = CID.encode(CID.create!(%{"text" => "b"}))
      head = %{rev: "3kbcq3p7ad42a", lthash: Commit.add_record(Lthash.new(), "c.a", "1", cid_a)}

      page1 = [
        %{
          "rev" => "3kbcq3p7ad42b",
          "collection" => "c.a",
          "rkey" => "1",
          "cid" => cid_b,
          "prev" => cid_a,
          "value" => %{"text" => "b"}
        }
      ]

      page2 = [
        %{
          "rev" => "3kbcq3p7ad42c",
          "collection" => "c.a",
          "rkey" => "2",
          "cid" => cid_a,
          "prev" => nil
        }
      ]

      final =
        Lthash.new()
        |> Commit.add_record("c.a", "1", cid_b)
        |> Commit.add_record("c.a", "2", cid_a)

      commit = %{head_commit(Lthash.digest(final)) | "rev" => "3kbcq3p7ad42c"}

      # A full last page has a cursor, so the walk ends on an empty page.
      pages = %{nil => {page1, "c1"}, "c1" => {page2, "c2"}, "c2" => {[], nil}}

      Process.put(:get, fn url ->
        query = URI.decode_query(URI.parse(url).query)
        assert query["since"] == "3kbcq3p7ad42a"
        Process.put(:keyids, [keyid() | Process.get(:keyids, [])])
        {ops, cursor} = Map.fetch!(pages, query["cursor"])
        body = %{"ops" => ops, "commit" => wire(commit)}
        body = if cursor, do: Map.put(body, "cursor", cursor), else: body
        {:ok, %{status: 200, headers: host_mac(:commit, commit), body: body}}
      end)

      opts = [http: SyncHTTP, kem_key: ctx.kem]

      assert {:ok, synced} = Sync.sync_repo(@repo_host, @space, @author, ctx.cred, head, opts)
      assert synced.commit == commit
      assert synced.rev == "3kbcq3p7ad42c"
      assert synced.ops == page1 ++ page2
      assert Sync.synced?(synced.lthash, commit)

      # A fresh secret for every page.
      keyids = Process.get(:keyids)
      assert length(keyids) == 3
      assert length(Enum.uniq(keyids)) == 3

      # From a state the ops do not lead to the commit: diverged.
      wrong_head = %{head | lthash: Lthash.new()}

      assert {:error, {:diverged, ^commit}} =
               Sync.sync_repo(@repo_host, @space, @author, ctx.cred, wrong_head, opts)
    end

    test "sync_repo refuses ops out of order, bad values, and a repeated cursor", ctx do
      commit = head_commit()
      cid_a = CID.encode(CID.create!(%{"text" => "a"}))
      head = %{rev: "3kbcq3p7ad42b", lthash: Lthash.new()}
      opts = [http: SyncHTTP, kem_key: ctx.kem]

      stage = fn ops, cursor ->
        Process.put(:get, fn _url ->
          body = %{"ops" => ops, "commit" => wire(commit)}
          body = if cursor, do: Map.put(body, "cursor", cursor), else: body
          {:ok, %{status: 200, headers: host_mac(:commit, commit), body: body}}
        end)
      end

      # An op at or before `since`.
      stage.(
        [%{"rev" => "3kbcq3p7ad42a", "collection" => "c.a", "rkey" => "1", "cid" => cid_a}],
        nil
      )

      assert {:error, :ops_out_of_order} =
               Sync.sync_repo(@repo_host, @space, @author, ctx.cred, head, opts)

      # A value that does not encode to its op's cid.
      stage.(
        [
          %{
            "rev" => "3kbcq3p7ad42c",
            "collection" => "c.a",
            "rkey" => "1",
            "cid" => cid_a,
            "value" => %{"text" => "not a"}
          }
        ],
        nil
      )

      assert {:error, {:record_cid_mismatch, "c.a/1"}} =
               Sync.sync_repo(@repo_host, @space, @author, ctx.cred, head, opts)

      # A host that keeps answering with the same cursor.
      stage.([], "same")

      assert {:error, :repeated_cursor} =
               Sync.sync_repo(@repo_host, @space, @author, ctx.cred, head, opts)
    end

    test "the running set hash detects divergence and converges through ops" do
      cid_a = "bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244"
      cid_b = "bafyreidpw4cbv6gr4ukh33z23pvvrpr3wi4gnpmi4doamlsl3sa4rgri2a"

      create = %{"collection" => "c.a", "rkey" => "1", "cid" => cid_a, "prev" => nil}
      update = %{"collection" => "c.a", "rkey" => "1", "cid" => cid_b, "prev" => cid_a}
      delete = %{"collection" => "c.a", "rkey" => "1", "cid" => nil, "prev" => cid_b}

      assert Lthash.empty?(Sync.apply_ops(Lthash.new(), [create, update, delete]))

      running = Sync.apply_ops(Lthash.new(), [create])
      refute Sync.synced?(running, :crypto.hash(:sha256, "not-the-state"))
      assert Sync.synced?(running, Lthash.digest(running))
    end
  end

  describe "repos and records" do
    test "get_repo verifies a full STAR archive end to end", ctx do
      records = [
        {"com.example.groupPost", "3jz1", %{"$type" => "com.example.groupPost", "text" => "one"}},
        {"com.example.groupPost", "3jz2", %{"$type" => "com.example.groupPost", "text" => "two"}}
      ]

      hash =
        Enum.reduce(records, Lthash.new(), fn {c, r, rec}, h ->
          Commit.add_record(h, c, r, CID.encode(CID.create!(rec)))
        end)

      commit = Commit.build(hash, %{space: @space, repo: @author, rev: "3kbcq3p7ad42a"})
      star = Repo.serialize(commit, records)

      Process.put(:get, fn url ->
        assert String.contains?(url, "/xrpc/com.atproto.space.getRepo?")

        headers = [
          {"content-type", "application/vnd.dasl.star"} | host_mac(:commit, commit)
        ]

        {:ok, %{status: 200, headers: headers, body: star}}
      end)

      assert {:ok, verified} =
               Sync.get_repo(@repo_host, @space, @author, ctx.cred,
                 http: SyncHTTP,
                 kem_key: ctx.kem
               )

      assert {_, ~s|mac=("atproto-space-commit";sf)| <> _} =
               List.keyfind(Process.get(:last_get_headers), "accept-signature", 0)

      assert length(verified.records) == 2
      assert Sync.synced?(verified.lthash, commit)
      assert Sync.synced?(verified.lthash, commit["data"])

      # Served for a different repo than asked: refused.
      assert {:error, :repo_mismatch} =
               Sync.get_repo(@repo_host, @space, "did:plc:other", ctx.cred,
                 http: SyncHTTP,
                 kem_key: ctx.kem
               )

      # Served as something other than STAR: refused.
      Process.put(:get, fn _url ->
        headers = [{"content-type", "application/octet-stream"} | host_mac(:commit, commit)]
        {:ok, %{status: 200, headers: headers, body: star}}
      end)

      assert {:error, {:unexpected_content_type, "application/octet-stream"}} =
               Sync.get_repo(@repo_host, @space, @author, ctx.cred,
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

      get =
        &Sync.get_record(@repo_host, @space, @author, "com.example.groupPost", &1, ctx.cred, &2)

      opts = [http: SyncHTTP, kem_key: ctx.kem]

      Process.put(:get, fn _url ->
        {:ok, %{status: 200, headers: host_mac(:record, {uri, cid}), body: body}}
      end)

      assert {:ok, ^body} = get.("3jz1", opts)

      {_, accept} = List.keyfind(Process.get(:last_get_headers), "accept-signature", 0)
      assert accept =~ ~s|mac=("atproto-space-record";sf);keyid="did:key:|
      assert accept =~ ~s(tag="atproto-space-record")

      # A value that does not encode to the MAC'd CID is refused.
      Process.put(:get, fn _url ->
        {:ok,
         %{
           status: 200,
           headers: host_mac(:record, {uri, cid}),
           body: %{body | "value" => %{"text" => "two"}}
         }}
      end)

      assert {:error, :record_cid_mismatch} = get.("3jz1", opts)

      # A MAC over another record's CID is refused.
      Process.put(:get, fn _url ->
        other = CID.create!(%{"text" => "two"})
        {:ok, %{status: 200, headers: host_mac(:record, {uri, other}), body: body}}
      end)

      assert {:error, {:invalid_space_mac, :record_mismatch}} = get.("3jz1", opts)

      # A record other than the one requested is refused.
      Process.put(:get, fn _url ->
        {:ok, %{status: 200, headers: host_mac(:record, {uri, cid}), body: body}}
      end)

      assert {:error, :record_uri_mismatch} = get.("3jz9", opts)
    end
  end

  describe "confirmRegistration" do
    test "the space host confirms a registration by its echoed challenge" do
      Process.put(:post, fn url ->
        assert url == @syncer <> "/xrpc/com.atproto.space.confirmRegistration"
        %{"challenge" => challenge} = Process.get(:last_post_body)
        {:ok, %{status: 200, headers: [], body: %{"challenge" => challenge}}}
      end)

      assert :ok = Sync.confirm_registration(@syncer, @space, "tok", http: SyncHTTP)

      assert %{"space" => @space, "token" => "tok", "challenge" => challenge} =
               Process.get(:last_post_body)

      assert byte_size(challenge) >= 16

      # A fresh challenge each time.
      assert :ok = Sync.confirm_registration(@syncer, @space, "tok", http: SyncHTTP)
      refute Process.get(:last_post_body)["challenge"] == challenge
    end

    test "a wrong echo, a refusal or no answer is RegistrationNotConfirmed" do
      for response <- [
            {:ok, %{status: 200, headers: [], body: %{"challenge" => "something else"}}},
            {:ok, %{status: 200, headers: [], body: %{}}},
            {:ok, %{status: 400, headers: [], body: %{"error" => "InvalidRequest"}}},
            {:error, :timeout}
          ] do
        Process.put(:post, fn _url -> response end)

        assert {:error, :registration_not_confirmed} =
                 Sync.confirm_registration(@syncer, @space, "tok",
                   http: SyncHTTP,
                   challenge: "c"
                 )
      end
    end

    test "the syncer decodes the request and echoes the challenge" do
      body = %{"space" => @space, "token" => "tok", "challenge" => "abc"}

      assert {:ok, %{space: @space, token: "tok", challenge: "abc"} = request} =
               Sync.decode_confirm_registration(body)

      assert Sync.confirm_registration_response(request) == %{"challenge" => "abc"}
      assert Sync.confirm_registration_response("abc") == %{"challenge" => "abc"}

      assert Sync.token_matches?("tok", "tok")
      refute Sync.token_matches?("tok", "other")
      refute Sync.token_matches?("tok", nil)

      for bad <- [
            Map.delete(body, "challenge"),
            %{body | "space" => "at://did:plc:x/app.bsky.feed.post/1"},
            %{body | "token" => String.duplicate("t", 513)},
            %{body | "challenge" => 1}
          ] do
        assert {:error, :invalid_request} = Sync.decode_confirm_registration(bad)
      end
    end
  end

  describe "notifySpaceUpdate" do
    @data :crypto.hash(:sha256, "state")
    @updates [
      %{
        type: :repo_write,
        repo: @author,
        repo_rev: "3kbcq3p7ad42a",
        data: @data,
        space_rev: "3kbcq3p7ad43a",
        prev_space_rev: "3kbcq3p7ad42c"
      },
      %{type: :repo_removed, repo: @author, space_rev: "3kbcq3p7ad44a", prev_space_rev: nil},
      %{type: :space_deleted},
      %{type: :registration_expired, space_rev: "3kbcq3p7ad44a"}
    ]

    test "every update type round-trips with its full $type" do
      types = [
        "com.atproto.space.defs#repoWrite",
        "com.atproto.space.defs#repoRemoved",
        "com.atproto.space.notifySpaceUpdate#spaceDeleted",
        "com.atproto.space.notifySpaceUpdate#registrationExpired"
      ]

      for {update, type} <- Enum.zip(@updates, types) do
        assert {:ok, %{"space" => @space, "token" => "tok", "update" => wire} = body} =
                 Sync.encode_space_update(@space, "tok", update)

        assert wire["$type"] == type

        assert {:ok, %{space: @space, token: "tok", update: ^update}} =
                 Sync.decode_space_update(body)
      end

      # The repoWrite wire form, exactly.
      {:ok, %{"update" => wire}} = Sync.encode_space_update(@space, "tok", hd(@updates))

      assert wire == %{
               "$type" => "com.atproto.space.defs#repoWrite",
               "repo" => @author,
               "repoRev" => "3kbcq3p7ad42a",
               "data" => %{"$bytes" => Base.encode64(@data, padding: false)},
               "spaceRev" => "3kbcq3p7ad43a",
               "prevSpaceRev" => "3kbcq3p7ad42c"
             }
    end

    test "update types are matched in full; unknown ones pass through as :unknown" do
      body = fn update -> %{"space" => @space, "token" => "tok", "update" => update} end

      # A short ref is not the full $type.
      assert {:ok, %{update: %{type: :unknown, value: %{"$type" => "#spaceDeleted"}}}} =
               Sync.decode_space_update(body.(%{"$type" => "#spaceDeleted"}))

      assert {:ok, %{update: %{type: :unknown}}} =
               Sync.decode_space_update(body.(%{"$type" => "com.example.future#update"}))

      # A known type that is malformed is refused.
      assert {:error, :invalid_update} =
               Sync.decode_space_update(
                 body.(%{"$type" => "com.atproto.space.notifySpaceUpdate#registrationExpired"})
               )

      assert {:error, :invalid_update} =
               Sync.decode_space_update(
                 body.(%{
                   "$type" => "com.atproto.space.defs#repoRemoved",
                   "repo" => @author,
                   "spaceRev" => "3kbcq3p7ad44a",
                   "prevSpaceRev" => "nope"
                 })
               )

      assert {:error, :invalid_update} = Sync.decode_space_update(body.(%{"repo" => @author}))

      # The November 5 forwarded notifyWrite / notifySpaceStatus bodies are not updates.
      assert {:error, :invalid_request} =
               Sync.decode_space_update(%{"space" => @space, "status" => "deleted"})

      assert {:error, :invalid_request} =
               Sync.decode_space_update(%{
                 body.(%{"$type" => "x"})
                 | "token" => String.duplicate("t", 513)
               })
    end

    test "notify_space_update posts the body to the endpoint, without auth" do
      Process.put(:post, fn url ->
        assert url == @syncer <> "/xrpc/com.atproto.space.notifySpaceUpdate"
        {:ok, %{status: 200, headers: [], body: ""}}
      end)

      update = %{type: :registration_expired, space_rev: "3kbcq3p7ad44a"}
      assert :ok = Sync.notify_space_update(@syncer, @space, "tok", update, http: SyncHTTP)

      assert Process.get(:last_post_body) == %{
               "space" => @space,
               "token" => "tok",
               "update" => %{
                 "$type" => "com.atproto.space.notifySpaceUpdate#registrationExpired",
                 "spaceRev" => "3kbcq3p7ad44a"
               }
             }

      # A syncer unregistering by rejecting the expiry notice.
      Process.put(:post, fn _url ->
        {:ok, %{status: 400, headers: [], body: %{"error" => "InvalidRequest"}}}
      end)

      assert {:error, {:http_error, 400, "InvalidRequest"}} =
               Sync.notify_space_update(@syncer, @space, "tok", update, http: SyncHTTP)

      assert {:error, :invalid_update} =
               Sync.notify_space_update(@syncer, @space, "tok", %{type: :unknown, value: %{}},
                 http: SyncHTTP
               )
    end
  end

  describe "notifyRepoUpdate" do
    test "the repo host notifies with service auth from the repo's account" do
      {:ok, repo_key} = JWK.generate(:secp256k1)
      Process.put(:repo_public_jwk, JWK.to_public(repo_key))
      data = :crypto.hash(:sha256, "state")

      Process.put(:post, fn url ->
        assert url == @space_host <> "/xrpc/com.atproto.space.notifyRepoUpdate"
        {:ok, %{status: 200, headers: [], body: ""}}
      end)

      update = %{space: @space, repo: @author, repo_rev: "3kbcq3p7ad42a", data: data}

      assert :ok =
               Sync.notify_repo_update(@space_host, update, [service_auth: [key: repo_key]],
                 http: SyncHTTP
               )

      body = Process.get(:last_post_body)

      assert body == %{
               "space" => @space,
               "repo" => @author,
               "repoRev" => "3kbcq3p7ad42a",
               "data" => %{"$bytes" => Base.encode64(data, padding: false)}
             }

      payload = Process.get(:last_service_auth)
      assert payload["iss"] == @author
      assert payload["aud"] == @authority <> "#atproto_pds"
      assert payload["lxm"] == "com.atproto.space.notifyRepoUpdate"

      # The space host's side: decode, then check the verified auth against it.
      assert {:ok, ^update} = Sync.decode_notify_repo_update(body)
      assert :ok = Sync.check_repo_update_auth(payload, update)
      assert :ok = Sync.check_repo_update_auth(%{payload | "aud" => @authority}, update)

      assert {:error, :iss_mismatch} =
               Sync.check_repo_update_auth(%{payload | "iss" => "did:plc:other"}, update)

      assert {:error, :aud_mismatch} =
               Sync.check_repo_update_auth(%{payload | "aud" => "did:plc:other"}, update)

      # Refusals keep their XRPC error name.
      Process.put(:post, fn _url ->
        {:ok, %{status: 400, headers: [], body: %{"error" => "FutureRev"}}}
      end)

      assert {:error, {:http_error, 400, "FutureRev"}} =
               Sync.notify_repo_update(@space_host, update, [service_auth: [key: repo_key]],
                 http: SyncHTTP
               )

      assert {:error, :invalid_auth} =
               Sync.notify_repo_update(@space_host, update, [], http: SyncHTTP)
    end

    test "decode_notify_repo_update/1 refuses malformed and November 5 bodies" do
      body = %{
        "space" => @space,
        "repo" => @author,
        "repoRev" => "3kbcq3p7ad42a",
        "data" => bytes(:crypto.hash(:sha256, "state"))
      }

      assert {:ok, %{repo_rev: "3kbcq3p7ad42a"}} = Sync.decode_notify_repo_update(body)

      # spaceRev/prevSpaceRev are gone from the method; extra fields are ignored.
      assert {:ok, decoded} =
               Sync.decode_notify_repo_update(Map.put(body, "spaceRev", "3kbcq3p7ad43a"))

      refute Map.has_key?(decoded, :space_rev)

      for bad <- [
            Map.delete(body, "data"),
            %{body | "repoRev" => "r"},
            %{body | "repo" => "alice"},
            %{body | "space" => "at://did:plc:x/app.bsky.feed.post/1"},
            %{body | "data" => %{"$bytes" => "not*base64!"}}
          ] do
        assert {:error, :invalid_request} = Sync.decode_notify_repo_update(bad)
      end
    end
  end
end
