defmodule SSHProto.Cipher do
  @moduledoc """
  `SSHProto.Cipher` behavior. All ciphers must implement this.
  """

  @type state :: any()

  @callback decrypt(state() | nil, binary()) ::
  {:ok, binary(), binary(), state()}
  | {:continue, state()}
  | {:error, any()}
end
