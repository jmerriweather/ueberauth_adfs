defmodule Ueberauth.Strategy.ADFS.OAuth do
  @moduledoc """

  ## OAuth2 for ADFS

  In ADFS >=3.0 setup a new Client using Powershell:
  ```powershell
  Add-AdfsClient -Name "OAUTH2 Client" -ClientId "unique-custom-client-id" -RedirectUri "http://localhost:4000/auth/adfs/callback"
  Add-ADFSRelyingPartyTrust -Name "OAUTH2 Client" -Identifier "http://localhost:4000/auth/adfs"
  Set-AdfsRelyingPartyTrust -IssuanceAuthorizationRulesFile "TransformRules.txt"
  ```
  In TransformRules.txt put the following:
  ```
  @RuleTemplate = "LdapClaims"
  @RuleName = "User Details"
  c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "groups", "userPrincipalName"), query = ";sAMAccountName,givenName,sn,mail,tokenGroups,userPrincipalName;{0}", param = c.Value);
  ```

  Add `adfs_url` and `client_id` to your configuration:
  ```elixir
  config :ueberauth, Ueberauth.Strategy.ADFS.OAuth,
    adfs_url: System.get_env("ADFS_URL"),
    client_id: System.get_env("ADFS_CLIENT_ID")
  ```
  """

  use OAuth2.Strategy

  alias OAuth2.Client
  alias OAuth2.Strategy.AuthCode

  @defaults [
    strategy: __MODULE__,
    request_opts: [ssl_options: [versions: [:'tlsv1.2']]]
  ]

  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, __MODULE__)

    with {value, new_config} when not is_nil(value) <- Keyword.pop(config, :adfs_url) do
      adfs_url = URI.parse(value)

      authorize_url = URI.merge(adfs_url, "adfs/oauth2/authorize") |> URI.to_string()
      token_url = URI.merge(adfs_url, "adfs/oauth2/token") |> URI.to_string()

      @defaults
        |> Keyword.put(:authorize_url, authorize_url)
        |> Keyword.put(:token_url, token_url)
        |> Keyword.merge(new_config)
        |> Keyword.merge(opts)
        |> Client.new
    end
  end

  def authorize_url!(params \\ [], opts \\ []) do
    opts
      |> client
      |> Client.authorize_url!(params)
  end

  def get_token!(params \\ [], opts \\ []) do
    opts
      |> client
      |> Client.get_token!(params)
  end

  # oauth2 Strategy Callbacks

  def authorize_url(client, params) do
    AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    new_client = client
      |> put_param(:grant_type, "authorization_code")
      |> put_header("Accept", "application/json")

    AuthCode.get_token(new_client, params, headers)
  end
end
