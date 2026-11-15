defmodule Exosphere.ATProto.Spaces.KemMacTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.{CID, Crypto}
  alias Exosphere.ATProto.Spaces.{Kem, Mac}
  alias Exosphere.ATProto.Spaces.StructuredFields, as: SF

  defp unhex(hex), do: Base.decode16!(hex, case: :lower)

  describe "Kem" do
    # The keys of the CFRG export-only DHKEM(P-256, HKDF-SHA256) vector, with
    # info "atproto-mac": the expected secret is atproto's (packages/space
    # tests/kem.test.ts @ d4def6e), computed with Go's crypto/hpke.
    @enc "04d804370b7e24b94749eb1dc8df6d4d4a5d75f9effad01739ebcad5c54a40d57aaa8b4190fc124dbde2e4f1e1d1b012a3bc4038157dc29b55533a932306d8d38d"
    @sk_em "2f18b059576a0ec5a17121c0fe7ec8f00ea86f7b046fa3889ac8f21f89dbd484"
    @sk_rm "62c3868357a464f8461d03aa0182c7cebcde841036aea7230ddc7339f1088346"
    @pk_rm "046c6bb9e1976402c692fef72552f4aaeedd83a5e5079de3d7ae732da0f397b15921fb9c52c9866affc8e29c0271a35937023a9245982ec18bab1eb157cf16fc33"
    @atproto_secret "2060e0558d1b34c10086bc137f849bb79ba59fcdc30544418e35c9cd301f0d0d"

    test "matches atproto's HPKE secret export vector on both sides" do
      {:ok, key_share} = Crypto.to_did_key(unhex(@enc), :p256)
      expected = unhex(@atproto_secret)

      assert {:ok, ^expected} = Kem.decapsulate(unhex(@sk_rm), key_share)

      {:ok, author_did} = Crypto.to_did_key(unhex(@pk_rm), :p256)

      assert {:ok, %{key_share: ^key_share, shared_secret: ^expected}} =
               Kem.encapsulate(author_did, ephemeral_private_key: unhex(@sk_em))

      # Raw points work as well as did:keys.
      assert {:ok, %{key_share: ^key_share, shared_secret: ^expected}} =
               Kem.encapsulate(unhex(@pk_rm), ephemeral_private_key: unhex(@sk_em))

      assert {:ok, ^expected} = Kem.decapsulate(unhex(@sk_rm), unhex(@enc))
    end

    test "both sides derive the same secret; every encapsulation is fresh" do
      {:ok, author} = Crypto.generate_keypair(:p256)
      {:ok, author_did} = Crypto.to_did_key(author.public_key, :p256)

      assert {:ok, %{key_share: "did:key:zDna" <> _ = share, shared_secret: secret}} =
               Kem.encapsulate(author_did)

      assert byte_size(secret) == 32
      assert {:ok, ^secret} = Kem.decapsulate(author.private_key, share)

      assert {:ok, %{key_share: other_share, shared_secret: other}} =
               Kem.encapsulate(author.public_key)

      refute other_share == share
      refute other == secret

      # Another author key derives another secret.
      {:ok, wrong} = Crypto.generate_keypair(:p256)
      refute {:ok, secret} == Kem.decapsulate(wrong.private_key, share)
    end

    test "only P-256 keys qualify" do
      {:ok, k1} = Crypto.generate_keypair(:secp256k1)
      {:ok, k1_did} = Crypto.to_did_key(k1.public_key, :secp256k1)

      assert {:error, :invalid_kem_key} = Kem.encapsulate(k1_did)
      assert {:error, :invalid_kem_key} = Kem.encapsulate(<<1, 2, 3>>)
      assert {:error, :invalid_kem_key} = Kem.encapsulate("did:key:nope")

      {:ok, author} = Crypto.generate_keypair(:p256)
      assert {:error, :invalid_kem_key} = Kem.decapsulate(author.private_key, k1_did)
      assert {:error, :invalid_kem_key} = Kem.decapsulate(author.private_key, "did:key:nope")
      assert {:error, :invalid_kem_private_key} = Kem.decapsulate(<<1, 2>>, k1_did)

      assert {:error, :invalid_ephemeral_key} =
               Kem.encapsulate(author.public_key, ephemeral_private_key: <<0::256>>)
    end
  end

  @key_share "did:key:zDnaExample"
  @space "at://did:example:space/space/app.bsky.group/test"
  @uri @space <> "/did:example:alice/app.bsky.feed.post/1"
  @commit %{
    "ver" => 1,
    "space" => @space,
    "repo" => "did:example:alice",
    "rev" => "3kbcq3p7ad400",
    "data" => :binary.copy(<<1>>, 32)
  }
  @commit_request ~s|mac=("atproto-space-commit";sf);keyid="#{@key_share}";tag="atproto-space-commit"|

  # The headers a host answers a fresh commit request with, and what the
  # syncer verifies them with. The two secrets differ only when a test says so.
  defp commit_mac(secret, host_secret \\ nil, commit \\ @commit) do
    {:ok, request} = Mac.parse_request(Mac.format_request(:commit, @key_share), :commit)
    headers = Mac.commit_headers(commit, Map.put(request, :shared_secret, host_secret || secret))
    {%{key_share: @key_share, shared_secret: secret}, headers}
  end

  defp record_mac(uri, cid, secret, host_secret \\ nil) do
    {:ok, request} = Mac.parse_request(Mac.format_request(:record, @key_share), :record)

    headers =
      Mac.record_headers(uri, cid, Map.put(request, :shared_secret, host_secret || secret))

    {%{key_share: @key_share, shared_secret: secret}, headers}
  end

  defp put(headers, name, value), do: List.keystore(headers, name, 0, {name, value})
  defp get(headers, name), do: headers |> List.keyfind(name, 0) |> elem(1)

  describe "Mac requests" do
    test "format the Accept-Signature header" do
      assert Mac.format_request(:commit, @key_share) == @commit_request

      assert Mac.format_request(:record, @key_share) ==
               ~s|mac=("atproto-space-record";sf);keyid="#{@key_share}";tag="atproto-space-record"|

      assert Mac.request_headers(:commit, @key_share) == [{"accept-signature", @commit_request}]
    end

    test "round-trip, keeping the label and the serialized parameters" do
      assert {:ok,
              %{
                profile: :commit,
                label: "mac",
                key_share: @key_share,
                signature_params: "(" <> _ = params
              }} = Mac.parse_request(@commit_request, :commit)

      assert params == String.replace_prefix(@commit_request, "mac=", "")
    end

    test "are found by tag, under any label; others are ignored" do
      header =
        ~s|other=("content-digest");tag="other", m=("atproto-space-commit";sf);keyid="#{@key_share}";tag="atproto-space-commit"|

      assert {:ok, %{label: "m", key_share: @key_share}} = Mac.parse_request(header, :commit)

      # Repeated field lines combine.
      assert {:ok, %{label: "m"}} =
               Mac.parse_request(String.split(header, ", ", parts: 2), :commit)

      assert :none = Mac.parse_request(nil, :commit)

      other =
        ~s|other=("content-digest");tag="other", | <> Mac.format_request(:record, @key_share)

      assert :none = Mac.parse_request(other, :commit)

      # A Token tag is not the String tag.
      assert :none =
               Mac.parse_request(
                 ~s|mac=("atproto-space-commit";sf);keyid="#{@key_share}";tag=atproto-space-commit|,
                 :commit
               )
    end

    test "accept an hmac-sha256 alg and no other" do
      assert {:ok, %{signature_params: params}} =
               Mac.parse_request(@commit_request <> ~s|;alg="hmac-sha256"|, :commit)

      assert String.ends_with?(params, ~s|;alg="hmac-sha256"|)

      assert {:error, {:invalid_space_mac, :wrong_signature_alg}} =
               Mac.parse_request(@commit_request <> ~s|;alg="ecdsa-p256-sha256"|, :commit)
    end

    test "are InvalidSpaceMac when malformed, repeated, or asking what the host can't do" do
      assert {:error, {:invalid_space_mac, :malformed_header}} = Mac.parse_request("???", :commit)

      request =
        ~s|("atproto-space-commit";sf);keyid="#{@key_share}";tag="atproto-space-commit"|

      assert {:error, {:invalid_space_mac, :multiple_requests}} =
               Mac.parse_request("a=#{request}, b=#{request}", :commit)

      for param <- ["created", "expires", ~s(nonce="abc")] do
        assert {:error, {:invalid_space_mac, :unsupported_parameter}} =
                 Mac.parse_request(@commit_request <> ";" <> param, :commit)
      end

      for components <- [
            ~s|("atproto-space-record";sf)|,
            ~s|("atproto-space-commit")|,
            ~s|("atproto-space-commit";sf "authorization")|,
            ~s|("atproto-space-commit";sf;bs)|
          ] do
        assert {:error, {:invalid_space_mac, :wrong_covered_components}} =
                 Mac.parse_request(
                   ~s|mac=#{components};keyid="#{@key_share}";tag="atproto-space-commit"|,
                   :commit
                 ),
               components
      end

      for keyid <- ["", ~s(;keyid="not-a-did"), ";keyid=did"] do
        assert {:error, {:invalid_space_mac, :invalid_keyid}} =
                 Mac.parse_request(
                   ~s|mac=("atproto-space-commit";sf)#{keyid};tag="atproto-space-commit"|,
                   :commit
                 ),
               keyid
      end
    end

    test "decapsulate with the author's KEM key; a non-P-256 key share is InvalidSpaceMac" do
      {:ok, author} = Crypto.generate_keypair(:p256)
      {:ok, kem} = Kem.encapsulate(author.public_key)

      {:ok, request} = Mac.parse_request(Mac.format_request(:record, kem.key_share), :record)

      assert {:ok, %{shared_secret: secret, label: "mac"}} =
               Mac.decapsulate(request, author.private_key)

      assert secret == kem.shared_secret

      {:ok, request} = Mac.parse_request(@commit_request, :commit)

      assert {:error, {:invalid_space_mac, :invalid_key}} =
               Mac.decapsulate(request, author.private_key)
    end
  end

  describe "commit MACs" do
    setup do: %{secret: :crypto.strong_rand_bytes(32)}

    test "cover an Atproto-Space-Commit header under the requested parameters", %{secret: secret} do
      {:ok, request} =
        Mac.parse_request(
          ~s|sig1=("atproto-space-commit";sf);keyid="#{@key_share}";tag="atproto-space-commit"|,
          :commit
        )

      headers = Mac.commit_headers(@commit, Map.put(request, :shared_secret, secret))

      covered =
        ~s|ver=1, repo="did:example:alice", space="#{@space}", rev="3kbcq3p7ad400", data=:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:|

      params = ~s|("atproto-space-commit";sf);keyid="#{@key_share}";tag="atproto-space-commit"|

      assert Enum.map(headers, &elem(&1, 0)) ==
               ["atproto-space-commit", "signature-input", "signature"]

      assert get(headers, "atproto-space-commit") == covered
      assert get(headers, "signature-input") == "sig1=" <> params

      # An RFC 9421 hmac-sha256 signature over the covered header.
      base = ~s|"atproto-space-commit";sf: #{covered}\n"@signature-params": #{params}|
      mac = :crypto.mac(:hmac, :sha256, secret, base)
      assert get(headers, "signature") == "sig1=:" <> Base.encode64(mac) <> ":"
    end

    test "verify under the same shared secret only", %{secret: secret} do
      {kem, headers} = commit_mac(secret)
      assert :ok = Mac.verify_commit(@commit, kem, headers)

      {kem, headers} = commit_mac(secret, :crypto.strong_rand_bytes(32))

      assert {:error, {:invalid_space_mac, :mac_mismatch}} =
               Mac.verify_commit(@commit, kem, headers)
    end

    test "verify from a Req-style map of lists, and from mixed-case names", %{secret: secret} do
      {kem, headers} = commit_mac(secret)
      assert :ok = Mac.verify_commit(@commit, kem, Map.new(headers, fn {k, v} -> {k, [v]} end))

      assert :ok =
               Mac.verify_commit(
                 @commit,
                 kem,
                 Enum.map(headers, fn {k, v} -> {String.upcase(k), v} end)
               )
    end

    test "reject a commit differing in any field", %{secret: secret} do
      {kem, headers} = commit_mac(secret)

      for {field, value} <- [
            {"ver", 2},
            {"repo", "did:example:bob"},
            {"space", @space <> "2"},
            {"rev", "3kbcq3p7ad401"},
            {"data", :binary.copy(<<2>>, 32)}
          ] do
        assert {:error, {:invalid_space_mac, :commit_mismatch}} =
                 Mac.verify_commit(Map.put(@commit, field, value), kem, headers),
               field
      end
    end

    test "reject a tampered header", %{secret: secret} do
      {kem, headers} = commit_mac(secret)
      covered = get(headers, "atproto-space-commit")

      tampered =
        put(headers, "atproto-space-commit", String.replace(covered, "ad400", "ad401"))

      assert {:error, {:invalid_space_mac, :mac_mismatch}} =
               Mac.verify_commit(%{@commit | "rev" => "3kbcq3p7ad401"}, kem, tampered)
    end

    test "cover the header as a structured field, so whitespace is insignificant", %{
      secret: secret
    } do
      {kem, headers} = commit_mac(secret)
      covered = get(headers, "atproto-space-commit")
      spaced = put(headers, "atproto-space-commit", String.replace(covered, ", ", ",   "))
      assert :ok = Mac.verify_commit(@commit, kem, spaced)
    end

    test "are found by tag under any label; two with the tag are refused", %{secret: secret} do
      {kem, headers} = commit_mac(secret)

      relabeled =
        Enum.map(headers, fn
          {name, "mac=" <> rest} when name in ["signature-input", "signature"] ->
            {name, "other=" <> rest}

          header ->
            header
        end)

      assert :ok = Mac.verify_commit(@commit, kem, relabeled)

      doubled =
        Enum.map(headers, fn
          {name, "mac=" <> rest = value} when name in ["signature-input", "signature"] ->
            {name, value <> ", other=" <> rest}

          header ->
            header
        end)

      assert {:error, {:invalid_space_mac, :multiple_http_signatures}} =
               Mac.verify_commit(@commit, kem, doubled)
    end

    # A MAC over the commit header with the given parameters, standing in for a
    # host that answers differently than this module does.
    defp mac_with_params(secret, params) do
      {kem, headers} = commit_mac(secret)
      covered = get(headers, "atproto-space-commit")
      base = ~s|"atproto-space-commit";sf: #{covered}\n"@signature-params": #{params}|
      mac = :crypto.mac(:hmac, :sha256, secret, base)

      headers =
        headers
        |> put("signature-input", "mac=" <> params)
        |> put("signature", "mac=:" <> Base.encode64(mac) <> ":")

      {kem, headers}
    end

    test "accept added, reordered, or omitted optional parameters", %{secret: secret} do
      for params <- [
            ~s|("atproto-space-commit";sf);tag="atproto-space-commit";created=1700000000;keyid="#{@key_share}"|,
            ~s|("atproto-space-commit";sf);tag="atproto-space-commit"|,
            ~s|("atproto-space-commit";sf);keyid="#{@key_share}";tag="atproto-space-commit";alg="hmac-sha256"|
          ] do
        {kem, headers} = mac_with_params(secret, params)
        assert :ok = Mac.verify_commit(@commit, kem, headers), params
      end
    end

    test "reject another keyid, alg, tag, or covered components", %{secret: secret} do
      for {params, reason} <- [
            {~s|("atproto-space-commit";sf);keyid="did:key:zDnaOther";tag="atproto-space-commit"|,
             :signature_keyid_mismatch},
            {~s|("atproto-space-commit";sf);keyid="#{@key_share}";tag="atproto-space-commit";alg="hmac-sha512"|,
             :wrong_signature_alg},
            {~s|("atproto-space-commit";sf);keyid="#{@key_share}";tag="other"|,
             :missing_http_signature},
            {~s|("atproto-space-commit");keyid="#{@key_share}";tag="atproto-space-commit"|,
             :wrong_covered_components}
          ] do
        {kem, headers} = mac_with_params(secret, params)

        assert {:error, {:invalid_space_mac, ^reason}} = Mac.verify_commit(@commit, kem, headers),
               params
      end
    end

    test "reject a response missing any of its three headers", %{secret: secret} do
      {kem, headers} = commit_mac(secret)

      for name <- ["atproto-space-commit", "signature-input", "signature"] do
        assert {:error, {:invalid_space_mac, _}} =
                 Mac.verify_commit(@commit, kem, List.keydelete(headers, name, 0)),
               name
      end

      assert {:error, {:invalid_space_mac, :missing_covered_header}} =
               Mac.verify_commit(@commit, kem, List.keydelete(headers, "atproto-space-commit", 0))

      assert {:error, {:invalid_space_mac, :malformed_covered_header}} =
               Mac.verify_commit(@commit, kem, put(headers, "atproto-space-commit", "ver=("))
    end
  end

  describe "record MACs" do
    setup do
      %{
        secret: :crypto.strong_rand_bytes(32),
        cid_a: CID.create!(%{"text" => "hello"}),
        cid_b: CID.create!(%{"text" => "world"})
      }
    end

    test "name the uri and cid, and verify under the same secret only", ctx do
      {kem, headers} = record_mac(@uri, ctx.cid_a, ctx.secret)

      assert get(headers, "atproto-space-record") ==
               ~s|uri="#{@uri}", cid="#{CID.encode(ctx.cid_a)}"|

      assert get(headers, "signature-input") ==
               ~s|mac=("atproto-space-record";sf);keyid="#{@key_share}";tag="atproto-space-record"|

      assert :ok = Mac.verify_record(@uri, ctx.cid_a, kem, headers)
      assert :ok = Mac.verify_record(@uri, CID.encode(ctx.cid_a), kem, headers)

      {kem, headers} = record_mac(@uri, ctx.cid_a, ctx.secret, :crypto.strong_rand_bytes(32))

      assert {:error, {:invalid_space_mac, :mac_mismatch}} =
               Mac.verify_record(@uri, ctx.cid_a, kem, headers)
    end

    test "cover the uri and the cid", ctx do
      {kem, headers} = record_mac(@uri, ctx.cid_a, ctx.secret)

      assert {:error, {:invalid_space_mac, :record_mismatch}} =
               Mac.verify_record(@uri <> "2", ctx.cid_a, kem, headers)

      assert {:error, {:invalid_space_mac, :record_mismatch}} =
               Mac.verify_record(@uri, ctx.cid_b, kem, headers)
    end

    test "are not accepted as commit MACs", ctx do
      {kem, headers} = record_mac(@uri, ctx.cid_a, ctx.secret)

      assert {:error, {:invalid_space_mac, :missing_http_signature}} =
               Mac.verify_commit(@commit, kem, headers)
    end
  end

  describe "end to end" do
    test "a syncer's request, a host's answer, and the syncer's check" do
      {:ok, author} = Crypto.generate_keypair(:p256)
      {:ok, author_did} = Crypto.to_did_key(author.public_key, :p256)

      # Syncer
      {:ok, kem} = Kem.encapsulate(author_did)
      [{"accept-signature", accept}] = Mac.request_headers(:commit, kem.key_share)

      # Host
      {:ok, request} = Mac.parse_request(accept, :commit)
      {:ok, params} = Mac.decapsulate(request, author.private_key)
      headers = Mac.commit_headers(@commit, params)

      # Syncer
      assert :ok = Mac.verify_commit(@commit, kem, headers)

      # A MAC requested under another key share is not this one.
      {:ok, other} = Kem.encapsulate(author_did)

      assert {:error, {:invalid_space_mac, :signature_keyid_mismatch}} =
               Mac.verify_commit(@commit, other, headers)
    end
  end

  test "the covered header's data is a padded Byte Sequence" do
    {:ok, [{"data", {{:bytes, data}, []}}]} =
      SF.parse_dictionary("data=:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:")

    assert data == :binary.copy(<<1>>, 32)
  end
end
