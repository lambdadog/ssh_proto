defmodule SshProto do
  @moduledoc """
  Documentation for `SshProto`.
  """

  defmodule Config do
    defstruct []

    @typedoc """
    SSH Protocol config.
    """
    @type t :: %__MODULE__{}
  end

  defmodule State do
    defstruct [
      decode_sequence_number: 0,
      encode_sequence_number: 0
    ]

    # TODO: consider moving sequence_number definition to another module?
    @typedoc """
    Packet sequence number used for message authentication.
    """
    @type sequence_number() :: 0..4294967296

    @typedoc """
    Struct to hold the protocol state. Should not be manipulated by caller.
    """
    @type t :: %__MODULE__{
      decode_sequence_number: sequence_number(),
      encode_sequence_number: sequence_number()
    }
  end

  @spec init(Config.t()) :: {:ok, State.t()} | {:error, any()}
  def init(_config) do
    {:ok, %State{}}
  end

  @doc """
  Decodes an SSH message. Due to the nature of the SSH protocol all messages
  must be decoded in order.
  """
  @spec decode(State.t(), binary()) :: {:ok, tuple()} | {:error, any()}
  def decode(_state, _data) do
    {:error, :unimplemented}
  end

  @doc """
  Encodes an SSH message. Due to the nature of the SSH protocol all messages
  must be encoded in order.
  """
  @spec encode(State.t(), tuple()) :: {:ok, binary()} | {:error, any()}
  def encode(_state, _msg) do
    {:error, :unimplemented}
  end
end
