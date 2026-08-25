defmodule Exosphere.ATProto.HTTP.Behaviour do
  @moduledoc """
  Behaviour for HTTP clients.

  Allows mocking HTTP requests in tests. `Exosphere.ATProto.HTTP` implements
  this behaviour and is the default adapter.
  """

  @type json_term ::
          nil
          | boolean()
          | number()
          | binary()
          | [json_term()]
          | %{optional(binary()) => json_term()}

  @type response :: %{
          status: pos_integer(),
          headers: [{String.t(), String.t()}],
          body: json_term()
        }

  @type request_opts :: [
          timeout: pos_integer(),
          headers: [{String.t(), String.t()}],
          json: json_term(),
          body: binary(),
          content_type: String.t(),
          follow_redirects: boolean()
        ]

  @callback get(String.t(), request_opts()) :: {:ok, response()} | {:error, term()}
  @callback post(String.t(), request_opts()) :: {:ok, response()} | {:error, term()}
  @callback request(atom(), String.t(), request_opts()) :: {:ok, response()} | {:error, term()}
end
