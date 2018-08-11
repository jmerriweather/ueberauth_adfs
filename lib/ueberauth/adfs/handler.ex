defmodule Ueberauth.Strategy.ADFS.Handler do
  alias Ueberauth.Auth.{Info, Credentials, Extra}
  @moduledoc """
  ADFS Handler behaviour.

  ```elixir
  defmodule MyApp.ADFSHandler do
    use Ueberauth.Strategy.ADFS.Handler
  end
  ```
  """

  @doc """
  Provides a place within the Ueberauth.Auth struct for information about the user.
  """
  @callback info(Plug.Conn.t()) :: %Info{}
  @doc """
  Provides information about the credentials of a request
  """
  @callback credentials(Plug.Conn.t()) :: %Credentials{}
  @doc """
  Provides a place for all raw information that was accumulated during the processing of the callback phase.
  """
  @callback extra(Plug.Conn.t()) :: %Extra{}

  @doc false
  defmacro __using__(_) do
    quote location: :keep do
      @behaviour Ueberauth.Strategy.ADFS.Handler

      alias Ueberauth.Auth.{Info, Credentials, Extra}

      @doc false
      def credentials(conn) do
        token = conn.private.adfs_token

        %Credentials{token: token.token}
      end

      @doc false
      def info(conn) do
        user = conn.private.adfs_user

        %Info{
          name: "#{user["given_name"]} #{user["family_name"]}",
          nickname: user["winaccountname"],
          email: user["email"]
        }
      end

      @doc false
      def extra(conn) do
        %Extra{
          raw_info: %{
            token: conn.private[:adfs_token],
            user: conn.private[:adfs_user]
          }
        }
      end

      defoverridable Ueberauth.Strategy.ADFS.Handler
    end
  end
end
