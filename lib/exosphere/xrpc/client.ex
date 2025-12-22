defmodule Exosphere.XRPC.Client do
  @moduledoc """
  Public-facing XRPC client built on top of `Exosphere.ATProto.XRPC.Client`.
  """

  @type t :: Exosphere.ATProto.XRPC.Client.t()

  @doc """
  Create a new XRPC client.

  See `Exosphere.ATProto.XRPC.Client.new/2` for options.
  """
  @spec new(String.t(), keyword()) :: t()
  defdelegate new(base_url, opts \\ []), to: Exosphere.ATProto.XRPC.Client

  @doc """
  Set the access token on a client.
  """
  @spec with_token(t(), String.t()) :: t()
  defdelegate with_token(client, token), to: Exosphere.ATProto.XRPC.Client

  @doc """
  Make an XRPC query (HTTP GET).
  """
  @spec query(t(), String.t(), keyword() | map()) :: {:ok, term()} | {:error, term()}
  defdelegate query(client, nsid, params \\ []), to: Exosphere.ATProto.XRPC.Client

  @doc """
  Make an XRPC procedure (HTTP POST).
  """
  @spec procedure(t(), String.t(), map() | keyword()) :: {:ok, term()} | {:error, term()}
  defdelegate procedure(client, nsid, body \\ %{}), to: Exosphere.ATProto.XRPC.Client

  @doc """
  Upload a blob to the PDS.
  """
  @spec upload_blob(t(), binary(), String.t()) :: {:ok, map()} | {:error, term()}
  def upload_blob(%Exosphere.ATProto.XRPC.Client{} = client, data, content_type)
      when is_binary(data) and is_binary(content_type) do
    Exosphere.ATProto.XRPC.Client.upload_blob(client, data, content_type)
  end
end
