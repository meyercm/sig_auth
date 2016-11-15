defmodule SigAuth.Plug do
  import Plug.Conn
  import ShorterMaps

  require Logger

  def init(%{} = opts), do: opts
  def init(opts) do
    Enum.into(opts, %{})
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
  def create_bundle(module, ~M{req_headers assigns} = conn) do
    body = assigns[:body]
    headers = req_headers
    nonce = SigAuth.get_nonce(req_headers) |> String.to_integer
    ~M{username signature} = SigAuth.extract_authorization(headers)
    ~M{module conn headers body username nonce signature}
  end

  @doc false
  def get_pk(~M{module username} = bundle) do
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
  def check_nonce(~M{module username nonce} = bundle) do
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
  def check_signature(~M{module username conn nonce body signature public_key}) do
    ~M{method request_path} = conn
    case SigAuth.valid?(method, request_path, nonce, body, signature, public_key) do
      false ->
        Logger.warn("SIGAUTH: invalid signature")
        false
      true ->
        apply(module, :update_nonce, [username, nonce])
        true
    end
  end

end
