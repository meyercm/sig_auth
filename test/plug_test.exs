defmodule SigAuth.PlugTest do
  use ExUnit.Case
  use Plug.Test

  test "sad path" do
    SigAuth.ExampleCredentialServer.start_link
    pub_key = SigAuth.load_key("./test/testing_id_rsa.pub")
    SigAuth.ExampleCredentialServer.add_user("bob", pub_key)

    priv_key = SigAuth.load_key("./test/testing_id_rsa")
    headers = SigAuth.sign("GET", "/wrong_path", 1, "", "bob", priv_key)
    assert "bob" == SigAuth.get_username(headers)
    conn = Enum.reduce(headers, conn(:get, "/"),
      fn {k, v}, conn ->
        put_req_header(conn, k, v)
      end)

    conn = SigAuth.Plug.call(conn, %{credential_server: SigAuth.ExampleCredentialServer})
    SigAuth.ExampleCredentialServer.stop
    assert {401, _, _} = sent_resp(conn)
  end

end
