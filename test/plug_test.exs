defmodule SigAuth.PlugTest do
  use ExUnit.Case
  use Plug.Test

  test "sad path: bad signature" do
    SigAuth.ExampleCredentialServer.start_link
    pub_key = SigAuth.load_key("./test/testing_id_rsa.pub")
    SigAuth.ExampleCredentialServer.add_user("bob", pub_key)

    priv_key = SigAuth.load_key("./test/testing_id_rsa")
    # intentionally sign the request using the wrong path
    headers = SigAuth.sign("GET", "/wrong_path", 1, "", "bob", priv_key)
    assert "bob" == SigAuth.get_username(headers)
    conn = Enum.reduce(headers, conn(:get, "/"),
      fn {k, v}, conn ->
        put_req_header(conn, k, v)
      end)

    conn = SigAuth.Plug.call(conn, %{credential_server: SigAuth.ExampleCredentialServer})
    assert {401, _, _} = sent_resp(conn)
    SigAuth.ExampleCredentialServer.stop
  end

  test "sad path: bad nonce" do
    SigAuth.ExampleCredentialServer.start_link
    pub_key = SigAuth.load_key("./test/testing_id_rsa.pub")
    SigAuth.ExampleCredentialServer.add_user("bob", pub_key)
    # update bob's nonce
    SigAuth.ExampleCredentialServer.update_nonce("bob", 1)

    # intentionally use an invalid nonce (<= old nonce)
    priv_key = SigAuth.load_key("./test/testing_id_rsa")
    headers = SigAuth.sign("GET", "/", 1, "", "bob", priv_key)
    assert "bob" == SigAuth.get_username(headers)
    conn = Enum.reduce(headers, conn(:get, "/"),
      fn {k, v}, conn ->
        put_req_header(conn, k, v)
      end)

    conn = SigAuth.Plug.call(conn, %{credential_server: SigAuth.ExampleCredentialServer})
    assert {401, _, _} = sent_resp(conn)
    SigAuth.ExampleCredentialServer.stop
  end

  test "sad path: bad user" do
    SigAuth.ExampleCredentialServer.start_link
    # don't put the user in.
    # pub_key = SigAuth.load_key("./test/testing_id_rsa.pub")
    # SigAuth.ExampleCredentialServer.add_user("bob", pub_key)

    priv_key = SigAuth.load_key("./test/testing_id_rsa")
    headers = SigAuth.sign("GET", "/", 1, "", "bob", priv_key)
    assert "bob" == SigAuth.get_username(headers)
    conn = Enum.reduce(headers, conn(:get, "/"),
      fn {k, v}, conn ->
        put_req_header(conn, k, v)
      end)

    conn = SigAuth.Plug.call(conn, %{credential_server: SigAuth.ExampleCredentialServer})
    assert {401, _, _} = sent_resp(conn)
    SigAuth.ExampleCredentialServer.stop
  end

  test "happy path" do
    SigAuth.ExampleCredentialServer.start_link
    pub_key = SigAuth.load_key("./test/testing_id_rsa.pub")
    SigAuth.ExampleCredentialServer.add_user("bob", pub_key)

    priv_key = SigAuth.load_key("./test/testing_id_rsa")
    headers = SigAuth.sign("GET", "/", 1, "", "bob", priv_key)
    assert "bob" == SigAuth.get_username(headers)
    conn = Enum.reduce(headers, conn(:get, "/"),
      fn {k, v}, conn ->
        put_req_header(conn, k, v)
      end)

    conn = SigAuth.Plug.call(conn, %{credential_server: SigAuth.ExampleCredentialServer})
    send_resp(conn, 200, "")
    assert {200, _, _} = sent_resp(conn)
    SigAuth.ExampleCredentialServer.stop
  end

end
