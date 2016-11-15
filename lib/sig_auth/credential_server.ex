defmodule SigAuth.CredentialServer do
  @callback get_public_key(binary) :: {:error, atom}|{:ok, any}
  @callback nonce_valid?(binary, integer) :: true|false
  @callback update_nonce(binary, integer) :: {:error, atom}|:ok

  def __using__(_opts) do
    quote do
      @behavior __MODULE__

      def get_public_key(_username), do: {:error, :not_implemented}
      def nonce_valid?(_username, _nonce), do: false
      def update_nonce(_username, _nonce), do: {:error, :not_implementd}

      defoverridable [
        get_public_key: 1,
        nonce_valid?: 2,
        update_nonce: 2,
      ]
    end
  end
end
