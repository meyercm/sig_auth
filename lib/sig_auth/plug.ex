defmodule SigAuth.Plug do
  @moduledoc """

  This Plug is the intended entry point for Server-side SigAuth use.

  In order to function, a CredentialServer module must be specified to provide
  the mapping from usenames to public keys.  See SigAuth.ExampleCredentialServer
  for more details.

  This plug should be specified early in the request Plug-chain, and protects
  all subsequent routes, e.g.:

  ```elixir
  defmodule MyApp.ApiRouter
    use Plug.Router

    plug :match
    plug :dispatch

    # Not Authenticated:
    forward "/public", to: MyApp.PublicApiRouter

    plug SigAuth.Plug, credential_server: MyApp.CredServer

    # Authenticated:
    forward "/private", to: MyApp.PrivateApiRouter
    # ...

  ```

  ## IMPORTANT NOTES:

   - This plug *must* read the body of the request to verify the signature. This
   may well break your plug pipeline (Parsers, especially).  Currently, the body
   is stored in `conn.assigns[:body]` after it is read.  If you have an idea for
   a more elegant solution, feel free to provide a pull-request.

   - The username in the "authorization" header is stored for convenience in
   `conn.assigns[:username]`; this field can be used for user / role based
   authentication of individual endpoints; `SigAuth` has proven that the
   requestor possesses the private key associated with that username.

  """
  import Plug.Conn
  import ShorterMaps

  require Logger

  def init(%{credential_server: _server} = opts), do: opts
  def init(opts) when is_list(opts) do
    Enum.into(opts, %{})
    |> init
  end

  def call(conn, ~M{credential_server}) do
    {:ok, body, conn} = read_body(conn)
    conn = assign(conn, :body, body)
    if signature_valid?(credential_server, conn) do
      assign(conn, :username, SigAuth.get_username(conn.req_headers))
    else
      conn
      |> send_resp(401, "")
      |> halt
    end
  end

  def signature_valid?(module, conn) do
    create_bundle(module, conn)
    |> get_pk
    |> check_nonce
    |> check_signature
  end

  @nonce_header SigAuth.nonce_header

  @doc false
  def create_bundle(module, ~M{req_headers, assigns} = conn) do
    body = assigns[:body]
    headers = req_headers
    nonce = SigAuth.get_nonce(req_headers)
    case SigAuth.extract_authorization(headers) do
      ~M{username, signature} ->
        ~M{module, conn, headers, body, username, nonce, signature}
      _ ->
        Logger.warn("SIGAUTH: request missing auth header")
        false
    end
  end

  @doc false
  def get_pk(false), do: false
  def get_pk(~M{module, username} = bundle) do
    case apply(module, :get_public_key, [username]) do
      {:error, reason} ->
        Logger.warn("SIGAUTH: public_key retrieval failed for #{username} (#{reason})")
        false
      {:ok, pk} ->
        Map.put(bundle, :public_key, pk)
    end
  end

  @doc false
  def check_nonce(false), do: false
  def check_nonce(~M{module, username, nonce} = bundle) do
    case apply(module, :nonce_valid?, [username, nonce]) do
      false ->
        Logger.warn("SIGAUTH: invalid nonce #{nonce} for #{username}")
        false
      true ->
        bundle
    end
  end

  @doc false
  def check_signature(false), do: false
  def check_signature(~M{module, username, conn, nonce, body, signature, public_key}) do
    ~M{method, request_path} = conn
    case SigAuth.valid?(method, request_path, nonce, body, signature, public_key) do
      false ->
        Logger.warn("SIGAUTH: invalid signature for #{username}")
        signature_components = ~M{method, request_path, nonce, body}
        Logger.debug("SIGAUTH: wrong signature: #{inspect signature}. components: #{inspect signature_components}")
        false
      true ->
        apply(module, :update_nonce, [username, nonce])
        true
    end
  end

end
