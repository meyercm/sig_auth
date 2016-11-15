defmodule SigAuth.ExampleCredentialServer do
  use GenServer
  use SigAuth.CredentialServer

  import ShorterMaps

  ##############################
  # API
  ##############################

  def start_link() do
    GenServer.start_link(__MODULE__, [], [name: __MODULE__])
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

  def get_public_key(username) do
    GenServer.call(__MODULE__, {:get_public_key, username})
  end

  def nonce_valid?(username, nonce) do
    GenServer.call(__MODULE__, {:nonce_valid?, username, nonce})
  end

  def update_nonce(username, nonce) do
    GenServer.call(__MODULE__, {:update_nonce, username, nonce})
  end

  #users: %{username => ~M{username last_nonce public_key}}
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

  def handle_call({:add_user, username, public_key}, ~M{users} = state) do
    nonce = 0
    users = Map.put(users, username, ~M{username public_key nonce})
    {:reply, :ok, %{state|users: users}}
  end
  def handle_call({:remove_user, username}, ~M{users} = state) do
    users = Map.delete(users, username)
    {:reply, :ok, %{state|users: users}}
  end
  def handle_call({:get_public_key, username}, ~M{users} = state) do
    reply = case Map.get(users, username) do
      nil -> {:error, :no_such_user}
      key -> {:ok, key}
    end
    {:reply, reply, state}
  end
  def handle_call({:nonce_valid?, username, nonce}, ~M{users} = state) do
    old_nonce = users[username][:nonce]
    reply = nonce > old_nonce
    {:reply, reply, state}
  end
  def handle_call({:update_nonce, username, nonce}, ~M{users} = state) do
    case Map.has_key?(users, username) do
      true ->
        users = put_in(users[username][:nonce], nonce)
        {:reply, :ok, %{state|users: users}}
      false ->
        {:reply, {:error, :no_such_user}, state}
    end
  end

  ##############################
  # Internal Calls
  ##############################

end
