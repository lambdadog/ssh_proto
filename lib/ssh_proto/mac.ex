defmodule SSHProto.MAC do
  defmodule State do
    defstruct [
      sequence_number: 0,
      algorithm_state: nil
    ]

    @type algorithm_state :: any()

    @type t :: %__MODULE__{
      sequence_number: SSHProto.Util.uint32(),
      algorithm_state: nil | algorithm_state()
    }
  end

  @callback validate(State.t(), binary(), binary()) ::
  {:ok, State.t()}
  | :continue
  | {:error, any()}
end
