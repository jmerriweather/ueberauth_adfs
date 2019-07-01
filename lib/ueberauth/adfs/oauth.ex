defmodule Ueberauth.Strategy.ADFS.OAuth do
  @moduledoc """
   ## OAuth2 for ADFS
  """

  use OAuth2.Strategy

  alias OAuth2.Client
  alias OAuth2.Strategy.AuthCode

  @defaults [
    strategy: __MODULE__,
    request_opts: [ssl_options: [versions: [:"tlsv1.2"]]]
  ]

  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.ADFS) || []

    with {value, new_config} when not is_nil(value) <- Keyword.pop(config, :adfs_url) do
      adfs_url = URI.parse(value)

      authorize_url = URI.merge(adfs_url, "adfs/oauth2/authorize") |> URI.to_string()
      token_url = URI.merge(adfs_url, "adfs/oauth2/token") |> URI.to_string()

      @defaults
      |> Keyword.put(:authorize_url, authorize_url)
      |> Keyword.put(:token_url, token_url)
      |> Keyword.merge(new_config)
      |> Keyword.merge(opts)
      |> Client.new()
    end
  end

  def authorize_url!(opts \\ []) do
    Client.authorize_url!(client(), opts)
  end

  def get_token(code, opts \\ []) do
    opts
    |> client()
    |> put_client_secret()
    |> Client.get_token(code: code)
  end

  defp put_client_secret(client = %{client_secret: client_secret}) when client_secret != nil do
    client
    |> put_param(:client_secret, client_secret)
  end
  defp put_client_secret(client), do: client

  def signout_url(params \\ %{}) do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.ADFS) || []

    with {value, _} when not is_nil(value) <- Keyword.pop(config, :adfs_url) do
      adfs_url = URI.parse(value)
      signout_return_address = Map.get(params, :redirect_uri)
      id_token = Map.get(params, :id_token, "")

      redirect =
        case signout_return_address do
          nil ->
            "adfs/oauth2/logout"

          address ->
            case id_token do
              nil ->
                "adfs/oauth2/logout?post_logout_redirect_uri=#{URI.encode(address)}"

              id ->
                "adfs/oauth2/logout?post_logout_redirect_uri=#{URI.encode(address)}&id_token_hint=#{
                  URI.encode(id)
                }"
            end
        end

      {
        :ok,
        adfs_url
        |> URI.merge(redirect)
        |> URI.to_string()
      }
    else
      _ -> {:error, :failed_to_logout}
    end
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    new_client =
      client
      |> put_param(:grant_type, "authorization_code")
      |> put_header("Accept", "application/json")

    AuthCode.get_token(new_client, params, headers)
  end
end
