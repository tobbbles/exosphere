defmodule Exosphere.ATProto.Spaces.Mac do
  @moduledoc """
  Commit and record MACs as RFC 9421 HTTP Message Signatures (proposal 0016,
  "Authenticity headers"; atproto `#5862`, in the November 12 alpha).

  Space repos carry no signatures: a repo host authenticates what it serves
  with an `hmac-sha256` signature (RFC 9421 §3.3.3) keyed by a per-request
  shared secret (`Spaces.Kem`), so a leaked response proves nothing to a third
  party. The MAC travels in HTTP headers, never in the repo data.

  ## Profiles

  | Profile | Tag and covered header | Methods |
  |---|---|---|
  | `:commit` | `atproto-space-commit` | `getLatestCommit`, `getRepo`, `listRepoOps` |
  | `:record` | `atproto-space-record` | `getRecord` |

  The syncer asks for a MAC with `Accept-Signature` (`request_headers/2`); the
  label (`mac`) is its own choice, `keyid` is its HPKE `enc` as a `did:key`,
  and the `tag` selects the profile:

      Accept-Signature: mac=("atproto-space-commit";sf);keyid="did:key:zDna...";tag="atproto-space-commit"

  The host answers (`commit_headers/2`, `record_headers/3`) with a header
  describing what it returned, and a signature over that header under the
  requested label, with the requested parameters verbatim:

      Atproto-Space-Commit: ver=1, repo="did:example:alice", space="at://...", rev="3mwcj3b6uak2f", data=:q3J0...=:
      Signature-Input: mac=("atproto-space-commit";sf);keyid="did:key:zDna...";tag="atproto-space-commit"
      Signature: mac=:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=:
      Vary: Accept-Signature

      Atproto-Space-Record: uri="at://...", cid="bafyrei..."

  The covered headers are Structured Field Dictionaries signed with the `sf`
  flag, so the signature base holds them re-serialized canonically: a
  verifier parses the header and serializes it again before computing the
  MAC.

  ## Host side

  1. `parse_request/2` the `Accept-Signature` value (requests with other tags
     are ignored; none for the profile is `:none`, which a request carrying
     a space credential must answer with `InvalidSpaceMac`),
  2. `decapsulate/2` it with the author's KEM private key,
  3. add `commit_headers/2` or `record_headers/3` to the response, plus
     `Vary: Accept-Signature` on every response of these methods, and
     `exposed_headers/1` in `Access-Control-Expose-Headers` for browsers.

  ## Syncer side

  `request_headers/2` with a fresh `Spaces.Kem.encapsulate/2` per request,
  then `verify_commit/3` or `verify_record/4` with that encapsulation and the
  response headers. Those check the MAC and that the covered header describes
  the given commit or record; checking that the commit's `repo` and `space`
  are the ones requested, and that the record's CID is the CID of the
  returned value, is the caller's part (`Spaces.Sync`).

  Every failure is `{:error, {:invalid_space_mac, reason}}` — the
  `InvalidSpaceMac` the host answers, and what a syncer reports.

  This replaces the November 5 `Atproto-Space-Want-Mac`/`Atproto-Space-Mac`
  headers and their length-prefixed MAC contexts; the proposal says not to
  support those.
  """

  alias Exosphere.ATProto.CID
  alias Exosphere.ATProto.Identity.DID
  alias Exosphere.ATProto.Spaces.{HttpSignature, Kem}
  alias Exosphere.ATProto.Spaces.StructuredFields, as: SF

  @commit_profile "atproto-space-commit"
  @record_profile "atproto-space-record"
  @alg "hmac-sha256"
  # The label this syncer requests its MAC under. A host answers under the
  # requested label, though a syncer finds the MAC by its tag.
  @label "mac"
  # The parameters a host fulfils. A syncer uses a new key share for each
  # request, so `created`, `expires` and `nonce` would add nothing.
  @request_params ~w(keyid tag alg)

  @type profile :: :commit | :record

  @typedoc """
  A MAC request as the host reads it from `Accept-Signature`: the syncer's
  label, its key share (`keyid`, a DID), and the requested signature
  parameters serialized — the host's MAC uses them as given.
  """
  @type request :: %{
          profile: profile(),
          label: String.t(),
          key_share: String.t(),
          signature_params: String.t()
        }

  @typedoc "A request with the shared secret decapsulated from its key share."
  @type mac_params :: %{
          required(:label) => String.t(),
          required(:signature_params) => String.t(),
          required(:shared_secret) => binary(),
          optional(atom()) => term()
        }

  @type error :: {:error, {:invalid_space_mac, atom()}}

  # -- names ------------------------------------------------------------------

  @doc "The profile's tag: `atproto-space-commit` or `atproto-space-record`."
  @spec tag(profile()) :: String.t()
  def tag(:commit), do: @commit_profile
  def tag(:record), do: @record_profile

  @doc """
  The (lowercase) name of the header the profile's MAC covers — the same
  string as its tag.
  """
  @spec covered_header(profile()) :: String.t()
  def covered_header(profile), do: tag(profile)

  @doc """
  The response headers a browser app needs exposed to read the MAC
  cross-origin (`Access-Control-Expose-Headers`).
  """
  @spec exposed_headers(profile()) :: [String.t()]
  def exposed_headers(profile), do: [covered_header(profile), "signature-input", "signature"]

  # -- requests (syncer) ------------------------------------------------------

  @doc """
  The `Accept-Signature` value asking for a MAC keyed by the shared secret
  for `key_share` (`Spaces.Kem.encapsulate/2`), e.g.
  `mac=("atproto-space-commit";sf);keyid="did:key:zDna...";tag="atproto-space-commit"`.
  """
  @spec format_request(profile(), String.t()) :: String.t()
  def format_request(profile, key_share) when is_binary(key_share) do
    SF.serialize_dictionary([
      {@label, {:inner_list, components(profile), [{"keyid", key_share}, {"tag", tag(profile)}]}}
    ])
  end

  @doc "The request headers asking for a MAC: `[{\"accept-signature\", format_request(...)}]`."
  @spec request_headers(profile(), String.t()) :: [{String.t(), String.t()}]
  def request_headers(profile, key_share),
    do: [{"accept-signature", format_request(profile, key_share)}]

  # -- requests (host) --------------------------------------------------------

  @doc """
  Find the MAC requested for `profile` in an `Accept-Signature` value (a
  string, a list of field lines, or `nil`), checking the host can fulfil it.

  Requests with other tags are ignored, so this is `:none` when nothing is
  requested for the profile. Otherwise the one request tagged for it must
  cover exactly `("<profile header>";sf)`, carry no parameters but `keyid`,
  `tag` and `alg`, name `alg="hmac-sha256"` if any, and have a DID `keyid`.
  Whether the key share is a usable P-256 key is `decapsulate/2`'s check.
  """
  @spec parse_request(String.t() | [String.t()] | nil, profile()) ::
          {:ok, request()} | :none | error()
  def parse_request(nil, _profile), do: :none
  def parse_request([], _profile), do: :none

  def parse_request(values, profile) when is_list(values),
    do: parse_request(Enum.join(values, ", "), profile)

  def parse_request(value, profile) when is_binary(value) do
    with {:ok, requests} <- parse_field(value) do
      case HttpSignature.members_with_tag(requests, tag(profile)) do
        [] -> :none
        [{label, member}] -> check_request(profile, label, member)
        [_, _ | _] -> invalid(:multiple_requests)
      end
    end
  end

  defp check_request(profile, label, {:inner_list, items, params} = member) do
    expected = HttpSignature.format_components(components(profile))

    cond do
      HttpSignature.format_components(items) != expected ->
        invalid(:wrong_covered_components)

      Enum.any?(params, fn {name, _} -> name not in @request_params end) ->
        invalid(:unsupported_parameter)

      match?({_, alg} when alg != @alg, List.keyfind(params, "alg", 0)) ->
        invalid(:wrong_signature_alg)

      true ->
        case List.keyfind(params, "keyid", 0) do
          {_, key_share} when is_binary(key_share) ->
            if DID.valid?(key_share) do
              {:ok,
               %{
                 profile: profile,
                 label: label,
                 key_share: key_share,
                 signature_params: SF.serialize_member(member)
               }}
            else
              invalid(:invalid_keyid)
            end

          _ ->
            invalid(:invalid_keyid)
        end
    end
  end

  @doc """
  Decapsulate a parsed request's key share with the author's KEM private key
  (32 bytes), returning the request with its `:shared_secret` — what
  `commit_headers/2` and `record_headers/3` take. A key share that is not a
  P-256 `did:key` is `InvalidSpaceMac` (`:invalid_key`); an unusable private
  key is the host's own fault, `{:error, :invalid_kem_private_key}`.
  """
  @spec decapsulate(request(), binary()) ::
          {:ok, mac_params()} | error() | {:error, :invalid_kem_private_key}
  def decapsulate(%{key_share: key_share} = request, kem_private_key) do
    case Kem.decapsulate(kem_private_key, key_share) do
      {:ok, secret} -> {:ok, Map.put(request, :shared_secret, secret)}
      {:error, :invalid_kem_key} -> invalid(:invalid_key)
      {:error, _} = error -> error
    end
  end

  # -- responses (host) -------------------------------------------------------

  @doc """
  The response headers for a commit: `atproto-space-commit` describing it,
  and `signature-input`/`signature` with the MAC over that header. `commit`
  is a `defs#commit` map with string keys (`"ver"`, `"repo"`, `"space"`,
  `"rev"`, and the 32-byte `"data"`).
  """
  @spec commit_headers(map(), mac_params()) :: [{String.t(), String.t()}]
  def commit_headers(
        %{"ver" => ver, "repo" => repo, "space" => space, "rev" => rev, "data" => data},
        params
      )
      when is_integer(ver) and is_binary(data) do
    header =
      SF.serialize_dictionary([
        {"ver", {ver, []}},
        {"repo", {repo, []}},
        {"space", {space, []}},
        {"rev", {rev, []}},
        {"data", {{:bytes, data}, []}}
      ])

    mac_headers(:commit, header, params)
  end

  @doc """
  The response headers for a record: `atproto-space-record` naming its `uri`
  and `cid` (a CID string or `%CID{}`), and `signature-input`/`signature`
  with the MAC over that header.
  """
  @spec record_headers(String.t(), String.t() | CID.t(), mac_params()) :: [
          {String.t(), String.t()}
        ]
  def record_headers(uri, cid, params) when is_binary(uri) do
    header = SF.serialize_dictionary([{"uri", {uri, []}}, {"cid", {cid_string(cid), []}}])
    mac_headers(:record, header, params)
  end

  defp mac_headers(profile, header, %{
         label: label,
         signature_params: signature_params,
         shared_secret: secret
       }) do
    base = HttpSignature.signature_base(components(profile), [header], signature_params)
    mac = :crypto.mac(:hmac, :sha256, secret, base)

    [
      {covered_header(profile), header},
      {"signature-input", label <> "=" <> signature_params},
      {"signature", SF.serialize_dictionary([{label, {{:bytes, mac}, []}}])}
    ]
  end

  # -- verification (syncer) --------------------------------------------------

  @doc """
  Verify a response's commit MAC, and that the `Atproto-Space-Commit` header
  it covers describes `commit` (`ver`, `repo`, `space`, `rev` and `data` all
  equal). `encapsulation` is what the request was made with
  (`Spaces.Kem.encapsulate/2`); `headers` the response's
  (`t:Spaces.HttpSignature.headers/0`).
  """
  @spec verify_commit(map(), Kem.encapsulation(), HttpSignature.headers()) :: :ok | error()
  def verify_commit(%{} = commit, encapsulation, headers) do
    with {:ok, fields} <- verify_mac(:commit, encapsulation, headers) do
      matches =
        SF.get_bare(fields, "ver") == commit["ver"] and
          SF.get_bare(fields, "repo") == commit["repo"] and
          SF.get_bare(fields, "space") == commit["space"] and
          SF.get_bare(fields, "rev") == commit["rev"] and
          SF.get_bare(fields, "data") == {:bytes, commit["data"]}

      if matches, do: :ok, else: invalid(:commit_mismatch)
    end
  end

  @doc """
  Verify a response's record MAC, and that the `Atproto-Space-Record` header
  it covers names `uri` and `cid` (a CID string or `%CID{}`). The caller
  computes `cid` from the returned record value, so this also checks the
  value.
  """
  @spec verify_record(
          String.t(),
          String.t() | CID.t(),
          Kem.encapsulation(),
          HttpSignature.headers()
        ) ::
          :ok | error()
  def verify_record(uri, cid, encapsulation, headers) when is_binary(uri) do
    with {:ok, fields} <- verify_mac(:record, encapsulation, headers) do
      if SF.get_bare(fields, "uri") == uri and SF.get_bare(fields, "cid") == cid_string(cid),
        do: :ok,
        else: invalid(:record_mismatch)
    end
  end

  # Check the MAC tagged for `profile`, returning the fields of the header it
  # covers.
  defp verify_mac(profile, %{key_share: key_share, shared_secret: secret}, headers) do
    headers = HttpSignature.normalize_headers(headers)

    required = %{
      tag: tag(profile),
      components: components(profile),
      alg: @alg,
      key_id: key_share
    }

    with {:ok, found} <-
           HttpSignature.find_signature(
             headers["signature-input"],
             headers["signature"],
             required
           )
           |> as_invalid(),
         {:ok, fields} <- covered_fields(headers[covered_header(profile)]) do
      # The `sf` flag covers the header as re-serialized from its parsed form.
      base =
        HttpSignature.signature_base(
          components(profile),
          [SF.serialize_dictionary(fields)],
          found.signature_params
        )

      if equal?(:crypto.mac(:hmac, :sha256, secret, base), found.signature),
        do: {:ok, fields},
        else: invalid(:mac_mismatch)
    end
  end

  defp covered_fields(value) when is_binary(value) do
    case parse_field(value) do
      {:ok, fields} -> {:ok, fields}
      {:error, {:invalid_space_mac, _}} -> invalid(:malformed_covered_header)
    end
  end

  defp covered_fields(_), do: invalid(:missing_covered_header)

  @doc "Constant-time comparison of two binaries (MACs, set hashes)."
  @spec equal?(binary(), binary()) :: boolean()
  def equal?(a, b) when is_binary(a) and is_binary(b),
    do: byte_size(a) == byte_size(b) and :crypto.hash_equals(a, b)

  def equal?(_, _), do: false

  # -- private ----------------------------------------------------------------

  # A MAC covers its profile's header, flagged `sf` as a structured field.
  defp components(profile), do: [{covered_header(profile), [{"sf", true}]}]

  defp parse_field(value) do
    case SF.parse_dictionary(value) do
      {:ok, dict} -> {:ok, dict}
      {:error, _} -> invalid(:malformed_header)
    end
  end

  defp as_invalid({:ok, _} = ok), do: ok
  defp as_invalid({:error, reason}), do: invalid(reason)

  defp cid_string(%CID{} = cid), do: CID.encode(cid)
  defp cid_string(cid) when is_binary(cid), do: cid

  defp invalid(reason), do: {:error, {:invalid_space_mac, reason}}
end
