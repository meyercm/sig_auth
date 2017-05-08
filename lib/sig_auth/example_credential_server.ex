defmodule SigAuth.ExampleCredentialServer do
  @moduledoc """

  This is an example of the `CredentialServer` behavior;  this GenServer holds
  the public keys of the authorized users for an application.

  In a production environment, rather than an in-memory store, a database or
  file-backed `CredentialServer` would be appropriate.

  To validate nonces, this server simply insists that nonces are monotonically
  increasing;  Linux Epoch time (perhaps given in milliseconds) is an obvious
  way to accomplish this goal.  Further validation could insist that the nonce
  represents a time +/- N minutes of the server's system time.

  ## Use

  ### Startup

  ```elixir
     iex> {:ok, _pid} = SigAuth.ExampleCredentialServer.start_link
     ...> pub_key = SigAuth.load_key("./test/testing_id_rsa.pub")
     ...> SigAuth.ExampleCredentialServer.add_user("bob", pub_key)
  ```

  ### Authorization

  In your top-level api routing plug:

  ```elixir
  defmodule MyApp.ApiRouter do
    use Plug.Router

    # invalid requests will not make it past this line:
    plug SigAuth.Plug, credential_server: SigAuth.ExampleCredentialServer

    # From here on, we are certain that the request is authentiated, and can
    # trust the client:

    plug :match
    plug :dispatch

    forward "/users", to: MyApp.Handlers.Users
    # ... and so on with the API routing

    match(_), do: send_resp(conn, 404, "")
  end
  ```

  """
  use GenServer
  use SigAuth.CredentialServer

  import ShorterMaps

  ##############################
  # API
  ##############################

  def start_link() do
    GenServer.start_link(__MODULE__, [], [name: __MODULE__])
  end

  def stop() do
    GenServer.call(__MODULE__, :stop)
  end

  def add_user(username, public_key) do
    GenServer.call(__MODULE__, {:add_user, username, public_key})
  end

  def remove_user(username) do
    GenServer.call(__MODULE__, {:remove_user, username})
  end

  ##############################
  # API for CredentialServer
  ##############################

  # These methods are used by SigAuth.Plug to validate incoming requests
  # any module that implements these methods can be used as a CredentialServer

  def get_public_key(username) do
    GenServer.call(__MODULE__, {:get_public_key, username})
  end

  def nonce_valid?(username, nonce) do
    GenServer.call(__MODULE__, {:nonce_valid?, username, nonce})
  end

  def update_nonce(username, nonce) do
    GenServer.call(__MODULE__, {:update_nonce, username, nonce})
  end

  #users: %{username => ~M{username, last_nonce, public_key}}
  defmodule State do
    @doc false
    defstruct [
      users: %{},
    ]
  end


  ##############################
  # GenServer Callbacks
  ##############################

  def init([]) do
    {:ok, %State{}}
  end

  def handle_call({:add_user, username, public_key}, _from, ~M{users} = state) do
    nonce = 0
    users = Map.put(users, username, ~M{username, public_key, nonce})
    {:reply, :ok, %{state|users: users}}
  end
  def handle_call({:remove_user, username}, _from, ~M{users} = state) do
    users = Map.delete(users, username)
    {:reply, :ok, %{state|users: users}}
  end
  def handle_call({:get_public_key, username}, _from, ~M{users} = state) do
    reply = case Map.get(users, username) do
      nil -> {:error, :no_such_user}
      %{public_key: key} -> {:ok, key}
    end
    {:reply, reply, state}
  end
  def handle_call({:nonce_valid?, username, nonce}, _from, ~M{users} = state) do
    old_nonce = users[username][:nonce]
    reply = nonce > old_nonce
    {:reply, reply, state}
  end
  def handle_call({:update_nonce, username, nonce}, _from, ~M{users} = state) do
    case Map.has_key?(users, username) do
      true ->
        users = put_in(users[username][:nonce], nonce)
        {:reply, :ok, %{state|users: users}}
      false ->
        {:reply, {:error, :no_such_user}, state}
    end
  end
  def handle_call(:stop, _from, state) do
    {:stop, :normal, :ok, state}
  end

  ##############################
  # Internal Calls
  ##############################

end
