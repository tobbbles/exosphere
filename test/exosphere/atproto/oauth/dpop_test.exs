defmodule Exosphere.ATProto.OAuth.DPoPTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.{DPoP, JWK, JWS}

  test "proof/4 builds a verifiable dpop+jwt with all claims" do
    {:ok, key} = DPoP.generate_key()

    assert {:ok, proof} =
             DPoP.proof(key, "POST", "https://pds.example.com:8443/xrpc/a?x=1",
               nonce: "n-1",
               ath: "tok"
             )

    assert {:ok, header, claims} = JWS.decode(proof)
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "ES256"
    assert header["jwk"]["kty"] == "EC"
    refute Map.has_key?(header["jwk"], "d")

    assert claims["htm"] == "POST"
    assert claims["htu"] == "https://pds.example.com:8443/xrpc/a"
    assert claims["nonce"] == "n-1"
    assert claims["ath"] == Base.url_encode64(:crypto.hash(:sha256, "tok"), padding: false)
    assert is_integer(claims["iat"])
    assert is_binary(claims["jti"])

    assert {:ok, _} = JWS.verify(header["jwk"], proof, ["ES256"])
  end

  test "proof/4 omits nonce and ath when not given" do
    {:ok, key} = DPoP.generate_key()
    {:ok, proof} = DPoP.proof(key, "GET", "https://pds.example.com/xrpc/b")
    {:ok, _header, claims} = JWS.decode(proof)
    refute Map.has_key?(claims, "nonce")
    refute Map.has_key?(claims, "ath")
  end

  test "every proof gets a fresh jti" do
    {:ok, key} = DPoP.generate_key()
    {:ok, p1} = DPoP.proof(key, "GET", "https://x.example.com/a")
    {:ok, p2} = DPoP.proof(key, "GET", "https://x.example.com/a")
    {:ok, _, c1} = JWS.decode(p1)
    {:ok, _, c2} = JWS.decode(p2)
    assert c1["jti"] != c2["jti"]
  end

  test "normalize_htu/1 per RFC 9449: lowercase, default ports dropped, query stripped" do
    assert DPoP.normalize_htu("HTTPS://Example.COM:443/xrpc/x?q=1#f") ==
             "https://example.com/xrpc/x"

    assert DPoP.normalize_htu("http://localhost:80/a") == "http://localhost/a"
    assert DPoP.normalize_htu("https://example.com") == "https://example.com/"
    assert DPoP.normalize_htu("https://example.com:8443/x") == "https://example.com:8443/x"
  end

  test "origin/1 is scheme://host[:non-default port]" do
    assert DPoP.origin("https://example.com/a/b?c=d") == "https://example.com"
    assert DPoP.origin("http://localhost:4999/x") == "http://localhost:4999"
    assert DPoP.origin("https://example.com:443/a") == "https://example.com"
  end

  test "nonce_header/1 and nonce_challenge?/1" do
    assert DPoP.nonce_header([{"dpop-nonce", "n"}]) == "n"
    assert DPoP.nonce_header([{"DPoP-Nonce", "n"}]) == "n"
    assert DPoP.nonce_header([{"content-type", "application/json"}]) == nil

    assert DPoP.nonce_challenge?(%{
             status: 400,
             headers: [{"dpop-nonce", "n"}],
             body: %{"error" => "use_dpop_nonce"}
           }) == "n"

    assert DPoP.nonce_challenge?(%{
             status: 400,
             headers: [{"dpop-nonce", "n"}],
             body: %{"error" => "invalid_request"}
           }) == nil

    assert DPoP.nonce_challenge?(%{status: 401, headers: [{"dpop-nonce", "n"}], body: %{}}) == "n"
    assert DPoP.nonce_challenge?(%{status: 200, headers: [{"dpop-nonce", "n"}], body: %{}}) == nil
    assert DPoP.nonce_challenge?(%{status: 401, headers: [], body: %{}}) == nil
  end
end

defmodule Exosphere.ATProto.OAuth.NonceStoreTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.DPoP.NonceStore

  # The store backs a shared ETS table; distinct origins per test keep
  # async:true safe.
  test "get/put/clear round-trip per origin" do
    origin = "https://as-#{:erlang.unique_integer([:positive])}.example.com"

    assert NonceStore.get(origin) == nil
    assert :ok = NonceStore.put(origin, "n-1")
    assert NonceStore.get(origin) == "n-1"
    assert :ok = NonceStore.put(origin, "n-2")
    assert NonceStore.get(origin) == "n-2"
    assert :ok = NonceStore.clear(origin)
    assert NonceStore.get(origin) == nil
  end
end

defmodule Exosphere.ATProto.OAuth.RequestTest do
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.{DPoP, JWS, Request}
  alias Exosphere.ATProto.OAuth.DPoP.NonceStore

  # Request.authorized/6 calls the http module synchronously from the
  # caller's process, so this fake can replay responses from the test
  # process's own dictionary.
  defmodule ReplayHTTP do
    def request(_method, _url, opts) do
      Process.put(:requests, [Keyword.get(opts, :headers, []) | Process.get(:requests, [])])
      Process.put(:bodies, [opts[:body] | Process.get(:bodies, [])])

      [next | rest] = Process.get(:responses)
      Process.put(:responses, rest)
      next
    end
  end

  defmodule ErrorHTTP do
    def request(_method, _url, _opts), do: {:error, :nxdomain}
  end

  test "authorized/6 retries once on a use_dpop_nonce challenge and caches the nonce" do
    {:ok, key} = DPoP.generate_key()
    url = "http://localhost:#{4000 + :erlang.unique_integer([:positive])}/par"

    Process.put(:responses, [
      {:ok,
       %{status: 400, headers: [{"dpop-nonce", "issued-1"}], body: %{"error" => "use_dpop_nonce"}}},
      {:ok,
       %{status: 201, headers: [{"dpop-nonce", "issued-1"}], body: %{"request_uri" => "urn:x"}}}
    ])

    assert {:ok, %{status: 201}} =
             Request.authorized(ReplayHTTP, :post, url, [form: %{"a" => "b"}], key, nil)

    requests = Process.get(:requests) |> Enum.reverse()
    assert length(requests) == 2

    [proof1, proof2] =
      Enum.map(requests, fn headers ->
        {"dpop", proof} = List.keyfind(headers, "dpop", 0)
        proof
      end)

    {:ok, _, c1} = JWS.decode(proof1)
    {:ok, _, c2} = JWS.decode(proof2)
    refute Map.has_key?(c1, "nonce")
    assert c2["nonce"] == "issued-1"

    # The form option became a urlencoded body on every attempt
    assert Process.get(:bodies) |> Enum.reverse() == ["a=b", "a=b"]

    # The issued nonce is cached for the origin
    assert NonceStore.get(DPoP.origin(url)) == "issued-1"
  after
    Process.delete(:responses)
    Process.delete(:requests)
    Process.delete(:bodies)
  end

  test "authorized/6 surfaces the response when a second challenge follows" do
    {:ok, key} = DPoP.generate_key()
    url = "http://localhost:#{5000 + :erlang.unique_integer([:positive])}/par"

    Process.put(:responses, [
      {:ok,
       %{status: 400, headers: [{"dpop-nonce", "n-1"}], body: %{"error" => "use_dpop_nonce"}}},
      {:ok,
       %{status: 400, headers: [{"dpop-nonce", "n-2"}], body: %{"error" => "use_dpop_nonce"}}}
    ])

    assert {:ok, %{status: 400}} = Request.authorized(ReplayHTTP, :post, url, [], key, nil)
    assert length(Process.get(:requests)) == 2
  after
    Process.delete(:responses)
    Process.delete(:requests)
    Process.delete(:bodies)
  end

  test "authorized/6 with an access token sends DPoP-scheme authorization and ath" do
    {:ok, key} = DPoP.generate_key()
    url = "http://localhost:#{6000 + :erlang.unique_integer([:positive])}/xrpc/x"

    Process.put(:responses, [{:ok, %{status: 200, headers: [], body: %{}}}])

    assert {:ok, %{status: 200}} = Request.authorized(ReplayHTTP, :get, url, [], key, "tok-1")

    [headers | _] = Process.get(:requests)
    assert {"authorization", "DPoP tok-1"} in headers

    {"dpop", proof} = List.keyfind(headers, "dpop", 0)
    {:ok, _, claims} = JWS.decode(proof)
    assert claims["ath"] == Base.url_encode64(:crypto.hash(:sha256, "tok-1"), padding: false)
  after
    Process.delete(:responses)
    Process.delete(:requests)
    Process.delete(:bodies)
  end

  test "authorized/6 passes transport errors through" do
    {:ok, key} = DPoP.generate_key()

    assert {:error, :nxdomain} =
             Request.authorized(ErrorHTTP, :post, "https://x.example.com/a", [], key, nil)
  end
end

defmodule Exosphere.ATProto.OAuth.DPoPVerifyTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias Exosphere.ATProto.OAuth.{DPoP, JWK, JWS}

  @credential "eyJ0eXAiOiJhdHByb3RvLXNwYWNlLWNyZWRlbnRpYWwrand0"
  @htu "https://pds.example.com/xrpc/com.atproto.space.getRepo"
  @now 1_800_000_000

  test "round-trips a proof for the request it was minted for" do
    {:ok, key} = DPoP.generate_key()
    {:ok, jkt} = JWK.thumbprint(JWK.to_public(key))
    {:ok, proof} = DPoP.proof(key, "GET", @htu <> "?did=did:plc:abc", ath: @credential, iat: @now)

    assert {:ok, %{jti: jti, jkt: ^jkt}} =
             DPoP.verify_proof(proof, "GET", @htu, credential: @credential, jkt: jkt, now: @now)

    assert is_binary(jti) and jti != ""
  end

  test "the request must match (htm and normalized htu)" do
    {:ok, key} = DPoP.generate_key()
    {:ok, proof} = DPoP.proof(key, "GET", @htu, ath: @credential, iat: @now)

    assert {:error, :proof_request_mismatch} =
             DPoP.verify_proof(proof, "POST", @htu, credential: @credential, now: @now)

    assert {:error, :proof_request_mismatch} =
             DPoP.verify_proof(proof, "GET", "https://pds.example.com/other",
               credential: @credential,
               now: @now
             )

    # Query strings don't count: the same proof covers any query on the path.
    assert {:ok, _} =
             DPoP.verify_proof(proof, "GET", @htu <> "?cursor=2",
               credential: @credential,
               now: @now
             )
  end

  test "ath must match the presented credential, and be absent on the token leg" do
    {:ok, key} = DPoP.generate_key()
    {:ok, bound} = DPoP.proof(key, "GET", @htu, ath: @credential, iat: @now)
    {:ok, plain} = DPoP.proof(key, "GET", @htu, iat: @now)

    assert {:ok, _} = DPoP.verify_proof(bound, "GET", @htu, credential: @credential, now: @now)

    assert {:error, :ath_mismatch} =
             DPoP.verify_proof(bound, "GET", @htu, credential: "other", now: @now)

    # On the token leg (no credential expected), a proof must omit ath...
    assert {:ok, _} = DPoP.verify_proof(plain, "GET", @htu, now: @now)
    assert {:error, :unexpected_ath} = DPoP.verify_proof(bound, "GET", @htu, now: @now)

    # ...and a proof without ath never matches a presented credential.
    assert {:error, :ath_mismatch} =
             DPoP.verify_proof(plain, "GET", @htu, credential: @credential, now: @now)
  end

  test "proofs age out (60s + skew)" do
    {:ok, key} = DPoP.generate_key()

    build = fn iat ->
      {:ok, proof} = DPoP.proof(key, "GET", @htu, iat: iat)
      proof
    end

    assert {:error, :proof_issued_in_future} =
             DPoP.verify_proof(build.(@now + 30), "GET", @htu, now: @now)

    assert {:error, :proof_expired} = DPoP.verify_proof(build.(@now - 90), "GET", @htu, now: @now)
    assert {:ok, _} = DPoP.verify_proof(build.(@now - 50), "GET", @htu, now: @now)
  end

  test "the signature must come from the embedded jwk, and match the binding" do
    {:ok, key} = DPoP.generate_key()
    {:ok, other} = DPoP.generate_key()
    {:ok, jkt} = JWK.thumbprint(JWK.to_public(key))
    {:ok, proof} = DPoP.proof(key, "GET", @htu, iat: @now)

    assert {:ok, %{jkt: ^jkt}} = DPoP.verify_proof(proof, "GET", @htu, now: @now)

    # A proof from the wrong key doesn't match the credential's binding.
    {:ok, other_proof} = DPoP.proof(other, "GET", @htu, iat: @now)

    assert {:error, :key_mismatch} =
             DPoP.verify_proof(other_proof, "GET", @htu, jkt: jkt, now: @now)

    # A forged signature over the same signing input fails verification.
    [h, p, _s] = String.split(proof, ".")
    forged = Enum.join([h, p, forged_sig(other, h <> "." <> p)], ".")
    assert {:error, _} = DPoP.verify_proof(forged, "GET", @htu, now: @now)
  end

  defp forged_sig(private_jwk, signing_input) do
    signer = JOSE.JWK.from_map(private_jwk)

    {_, %{"signature" => sig}} =
      JOSE.JWS.sign(signer, signing_input, %{"alg" => "ES256"})

    sig
  end
end
