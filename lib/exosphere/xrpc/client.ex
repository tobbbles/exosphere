defmodule Exosphere.XRPC.Client do
  @moduledoc """
  Public-facing XRPC client built on top of `Exosphere.ATProto.XRPC.Client`.
  """

  alias Exosphere.ATProto.XRPC.Client, as: ATClient

  @type t :: ATClient.t()

  @doc """
  Create a new XRPC client.

  See `Exosphere.ATProto.XRPC.Client.new/2` for options.
  """
  @spec new(String.t(), keyword()) :: t()
  defdelegate new(base_url, opts \\ []), to: ATClient

  @doc """
  Set the access token on a client.
  """
  @spec with_token(t(), String.t()) :: t()
  defdelegate with_token(client, token), to: ATClient

  @doc """
  Make an XRPC query (HTTP GET).
  """
  @spec query(t(), String.t(), keyword() | map()) :: {:ok, term()} | {:error, term()}
  defdelegate query(client, nsid, params \\ []), to: ATClient

  @doc """
  Make an XRPC procedure (HTTP POST).
  """
  @spec procedure(t(), String.t(), map() | keyword()) :: {:ok, term()} | {:error, term()}
  defdelegate procedure(client, nsid, body \\ %{}), to: ATClient

  @doc """
  Upload a blob to the PDS.
  """
  @spec upload_blob(t(), binary(), String.t()) :: {:ok, map()} | {:error, term()}
  def upload_blob(%ATClient{} = client, data, content_type)
      when is_binary(data) and is_binary(content_type) do
    ATClient.upload_blob(client, data, content_type)
  end
end
