defmodule SigAuth.CredentialServer do
  @moduledoc """
  This module represents the contract that every Credential Server must adhere
  to. These methods are used by the `SigAuth.Plug` module to streamline request
  authentication and nonce maintenince.

  During each request, the plug will first request the public key from the
  credential server, calling `get_public_key(username)`.  The plug will then
  ask the credential server to validate the submitted nonce, calling
  `nonce_valid(username, nonce)`.  If the signature is valid, then the plug will
  notify the credential server by calling `update_nonce(username, integer)`.

  At each of these steps, a failure will abort the rest of the chain and deny
  the authorization request.
  """
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
