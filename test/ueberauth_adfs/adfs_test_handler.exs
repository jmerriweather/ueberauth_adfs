defmodule Ueberauth.Strategy.ADFSTestHandler do
  use Ueberauth.Strategy.ADFS.Handler

  @impl true
  def credentials(conn) do
    token = conn.private.adfs_token

    %Credentials{token: token.token, other: %{handler: true}}
  end

  @impl true
  def info(conn) do
    user = conn.private.adfs_user

    %Info{
      name: "#{user["given_name"]} #{user["family_name"]}",
      nickname: user["winaccountname"],
      email: user["email"],
      location: "handler"
    }
  end

  @impl true
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private[:adfs_token],
        user: conn.private[:adfs_user],
        with_handler: true
      }
    }
  end
end
