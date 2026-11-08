defmodule Exosphere.ExternalSpaceTest do
  @moduledoc """
  A live Spaces round trip: delegation → credential → writer set → verified STAR archive.

  This is the `spaces/alpha` promotion checklist's "one `@tag :external` round
  trip against a stable alpha PDS", written so it can be run the moment such a
  PDS exists. Everything else in the Spaces suite is exercised through
  `HTTP.Behaviour` mocks, which check the requests we *send* but can only ever
  confirm the shapes we already believe in. This one talks to a real host.

  It needs credentials, so it reads them from the environment and skips itself
  when they are absent:

      EXOSPHERE_SPACE_PDS=https://alpha.pds.example \\
      EXOSPHERE_SPACE_URI=at://did:plc:.../space/com.example.type/3l... \\
      EXOSPHERE_SPACE_TOKEN=<OAuth access token, space-scoped> \\
      mix test --only external

  `EXOSPHERE_SPACE_HOST` is optional: without it the space host is resolved
  from the authority's DID document, which is what a real reader does and is
  itself worth exercising.

  A skip here is not a pass. Until this has actually run green against a live
  alpha PDS, the Spaces client's wire compatibility rests on mocks, and the
  branch should stay draft.
  """

  use ExUnit.Case, async: true

  alias Exosphere.ATProto.AtUri
  alias Exosphere.ATProto.Identity.{DID, Document}
  alias Exosphere.ATProto.Spaces.{Credential, HttpSignature, Sync}

  @moduletag :external
  @moduletag timeout: 300_000

  setup do
    pds = System.get_env("EXOSPHERE_SPACE_PDS")
    space = System.get_env("EXOSPHERE_SPACE_URI")
    token = System.get_env("EXOSPHERE_SPACE_TOKEN")

    if is_nil(pds) or is_nil(space) or is_nil(token) do
      # Not a silent skip: say exactly what is missing, so a run that proves
      # nothing cannot be mistaken for a run that proved something.
      {:ok, skip: "set EXOSPHERE_SPACE_PDS, EXOSPHERE_SPACE_URI and EXOSPHERE_SPACE_TOKEN"}
    else
      {:ok, pds: pds, space: space, token: token, skip: nil}
    end
  end

  test "a reader's flow, end to end against a live alpha PDS", context do
    if context.skip do
      IO.puts("\n  [skipped] live Spaces round trip: #{context.skip}")
    else
      %{pds: pds, space: space_ref, token: token} = context

      # 1. Resolve the authority and find its space host.
      {:ok, %{authority: authority}} = AtUri.parse(space_ref)
      {:ok, document} = DID.resolve(authority)

      space_host =
        System.get_env("EXOSPHERE_SPACE_HOST") ||
          case Document.get_space_host_endpoint(document) do
            {:ok, endpoint} -> endpoint
            _ -> flunk("the authority's DID document advertises no space host")
          end

      # 2. A delegation token from the user's own PDS, under space-scoped OAuth.
      assert {:ok, delegation} =
               Credential.get_delegation_token(pds, space_ref,
                 headers: [{"authorization", "Bearer " <> token}]
               )

      # 3. Exchange it at the space host for a credential bound to a fresh
      #    P-256 key; every later request is signed by that key.
      assert {:ok, key} = HttpSignature.generate_key()

      assert {:ok, credential} =
               Credential.mint(space_host, space_ref, delegation, key: key)

      # 4. The writer set.
      assert {:ok, %{repos: repos}} = Sync.list_repos(space_host, space_ref, credential)
      assert is_list(repos)

      # 5. Each member's repo, verified: a synced copy that is also an
      #    authenticated one. This is the claim the whole design rests on, and
      #    the only place it meets bytes the reference implementation produced.
      for repo <- repos do
        {:ok, author_doc} = DID.resolve(repo.did)

        {:ok, kem_key} = Document.get_kem_key(author_doc)

        assert {:ok, verified} =
                 Sync.get_repo(pds, space_ref, repo.did, credential, kem_key: kem_key),
               "full-archive verification failed for #{repo.did}"

        assert Sync.synced?(verified.lthash, repo.data),
               "the verified set hash does not match the writer set's commit data"
      end
    end
  end
end
