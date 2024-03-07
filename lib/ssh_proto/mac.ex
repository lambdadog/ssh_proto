defmodule SSHProto.MAC do
  @typedoc """
  Packet sequence number used for message authentication.
  """
  @type sequence_number() :: 0..4294967296

  @doc """
  Increment MAC sequence number. This function is used to implement proper
  overflow behavior for uint32, since all numbers on the BEAM are bigints.
  """
  @spec increment_sequence_number(sequence_number()) :: sequence_number()
  def increment_sequence_number(4294967296),
    do: 0

  def increment_sequence_number(num),
    do: num + 1
end
