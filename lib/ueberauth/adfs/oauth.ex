defmodule Ueberauth.Strategy.ADFS.OAuth do
  @moduledoc """
  OAuth2 for ADFS
  Add 'adfs_url', 'adfs_metadata_url', 'client_id' and 'resource_identifier'
  to your configuration:
  config :ueberauth, Ueberauth.Strategy.ADFS,
    adfs_url: "https://adfs.url",
    adfs_metadata_url: "https://path.to/FederationMetadata.xml",
    client_id: "the_client",
    resource_identifier: "the_resource_id"

  On the ADFS server add a new Client:
  Add-AdfsClient -Name "the_client_name" -ClientId "the_client" -RedirectUri "https://my_application.url/auth/adfs/callback"

  Setup the relying party trust as usual, be sure to return at least the e-mail in the clams.
  """

  use OAuth2.Strategy

  alias OAuth2.Client
  alias OAuth2.Strategy.AuthCode

  @defaults [
    strategy: __MODULE__,
    request_opts: [ssl_options: [versions: [:"tlsv1.2"]]]
  ]

  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.ADFS)

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
    opts
    |> client()
    |> Client.authorize_url!()
  end

  def get_token(code, opts \\ []) do
    opts
    |> client()
    |> Client.get_token(code: code)
  end

  def signout_url(params \\ %{}) do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.ADFS)

    with {value, _} when not is_nil(value) <- Keyword.pop(config, :adfs_url) do
      adfs_url = URI.parse(value)
      signout_return_address = Map.get(params, :redirect_uri)

      redirect =
        case signout_return_address do
          nil -> "adfs/ls/?wa=wsignout1.0"
          address -> "adfs/ls/?wa=wsignout1.0&wreply=#{address}"
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
