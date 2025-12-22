defmodule Exosphere.ATProto.HTTP.Behaviour do
  @moduledoc """
  Behaviour for HTTP clients.

  Allows mocking HTTP requests in tests.
  """

  @type response :: %{
          status: pos_integer(),
          headers: [{String.t(), String.t()}],
          body: binary() | map()
        }

  @type request_opts :: [
          timeout: pos_integer(),
          headers: [{String.t(), String.t()}],
          json: map(),
          body: binary()
        ]

  @callback get(String.t(), request_opts()) :: {:ok, response()} | {:error, term()}
  @callback post(String.t(), request_opts()) :: {:ok, response()} | {:error, term()}
  @callback request(atom(), String.t(), request_opts()) :: {:ok, response()} | {:error, term()}
end
