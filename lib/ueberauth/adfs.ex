defmodule Ueberauth.Strategy.ADFS do
  @moduledoc """
  ADFS Strategy for Überauth.

   In ADFS Server setup a new Client using Powershell:
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

  Add 'adfs_url', 'adfs_metadata_url', 'client_id', 'resource_identifier' and optionally adfs_handler
  to your configuration:
  ```elixir
  config :ueberauth, Ueberauth.Strategy.ADFS,
    adfs_url: "https://adfs.url",
    adfs_metadata_url: "https://path.to/FederationMetadata.xml",
    adfs_handler: MyApp.ADFSHandler, # Use custom handler to extract information from the token claims
    client_id: "the_client",
    resource_identifier: "the_resource_id"
  ```

  An example custom ADFS handler
  ```elixir
  defmodule MyApp.ADFSHandler do
    use Ueberauth.Strategy.ADFS.Handler

    def credentials(conn) do
      token = conn.private.adfs_token

      %Credentials{
        expires: token.claims["exp"] != nil,
        expires_at: token.claims["exp"],
        scopes: token.claims["aud"],
        token: token.token
      }
    end

    @doc false
    def info(conn) do
      user = conn.private.adfs_user

      %Info{
        nickname: user["winaccountname"],
        name: "\#{user["given_name"]} \#{user["family_name"]}",
        email: user["email"],
        first_name: user["given_name"],
        last_name: user["family_name"]
      }
    end

    @doc false
    def extra(conn) do
      user = conn.private.adfs_user

      %Extra{
        raw_info: %{
          token: conn.private[:adfs_token],
          user: user,
          groups: user["groups"]
        }
      }
    end
  end
  ```
  """

  import SweetXml

  use Ueberauth.Strategy

  alias Ueberauth.Strategy.ADFS.OAuth

  def handle_request!(conn) do
    if __MODULE__.configured?() do
      redirect_to_authorization(conn)
    else
      redirect!(conn, "/")
    end
  end

  def logout(conn, token) do
    params = %{redirect_uri: callback_url(conn), token: token}

    with {:ok, signout_url} <- OAuth.signout_url(params) do
      redirect!(conn, signout_url)
    else
      _ ->
        set_errors!(conn, [error("Logout Failed", "Failed to logout, please close your browser")])
    end
  end

  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    with {:ok, client} <- OAuth.get_token(code, redirect_uri: callback_url(conn)) do
      fetch_user(conn, client)
    else
      {:error, %{reason: reason}} ->
        set_errors!(conn, [error("Authentication Error", reason)])

      {:error, %OAuth2.Response{body: %{"error_description" => reason}}} ->
        set_errors!(conn, [error("Authentication Error", reason)])
    end
  end

  def handle_callback!(
        %Plug.Conn{params: %{"error" => error, "error_description" => error_description}} = conn
      ) do
    set_errors!(conn, [error(error, error_description)])
  end

  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  def handle_cleanup!(conn) do
    conn
    |> put_private(:adfs_user, nil)
    |> put_private(:adfs_token, nil)
    |> put_private(:adfs_handler, nil)
  end

  def uid(conn) do
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string

    conn.private.adfs_user[uid_field]
  end

  def credentials(conn) do
    apply(conn.private.adfs_handler, :credentials, [conn])
  end

  def info(conn) do
    apply(conn.private.adfs_handler, :info, [conn])
  end

  def extra(conn) do
    apply(conn.private.adfs_handler, :extra, [conn])
  end

  def configured? do
    :ueberauth
    |> Application.get_env(__MODULE__)
    |> env_present?
  end

  defp fetch_user(conn, %{token: %{access_token: access_token}}) do
    url = config(:adfs_metadata_url)

    adfs_handler = config(:adfs_handler) || Ueberauth.Strategy.ADFS.DefaultHandler

    conn = put_private(conn, :adfs_handler, adfs_handler)

    with {:ok, %HTTPoison.Response{body: metadata}} <-
           HTTPoison.get(url, [], ssl: [versions: [:"tlsv1.2"]]),
         true <- String.starts_with?(metadata, "<EntityDescriptor"),
         {:ok, certificate} <- cert_from_metadata(metadata) do
      key =
        certificate
        |> JOSE.JWK.from_pem()
        |> Joken.rs256()

      jwt =
        access_token
        |> Joken.token()
        |> Joken.with_signer(key)
        |> Joken.verify()

      conn = put_private(conn, :adfs_token, jwt)

      with %Joken.Token{claims: claims_user} <- jwt do
        put_private(conn, :adfs_user, claims_user)
      else
        _ -> set_errors!(conn, [error("token", "unauthorized")])
      end
    else
      {:error, %HTTPoison.Error{}} -> set_errors!(conn, [error("metadata_url", "not_found")])
      {:error, :cert_not_found} -> set_errors!(conn, [error("certificate", "not_found")])
      false -> set_errors!(conn, [error("metadata", "malformed")])
    end
  end

  defp cert_from_metadata(metadata) when is_binary(metadata) do
    metadata
    |> xpath(~x"//EntityDescriptor/ds:Signature/KeyInfo/X509Data/X509Certificate/text()"s)
    |> build_cert()
  end

  defp build_cert(cert_content)
       when is_binary(cert_content) and byte_size(cert_content) > 0 do
    {:ok,
     """
     -----BEGIN CERTIFICATE-----
     #{cert_content}
     -----END CERTIFICATE-----
     """}
  end

  defp build_cert(_), do: {:error, :cert_not_found}

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end

  defp config(option) do
    :ueberauth
    |> Application.get_env(__MODULE__)
    |> Keyword.get(option)
  end

  defp redirect_to_authorization(conn) do
    authorize_url =
      conn.params
      |> Map.put(:resource, config(:resource_identifier))
      |> Map.put(:redirect_uri, callback_url(conn))
      |> OAuth.authorize_url!()

    redirect!(conn, authorize_url)
  end

  defp env_present?(env) do
    if Keyword.has_key?(env, :adfs_url)
    && Keyword.has_key?(env, :adfs_metadata_url)
    && Keyword.has_key?(env, :client_id)
    && Keyword.has_key?(env, :resource_identifier) do
      env
      |> Keyword.take([:adfs_url, :adfs_metadata_url, :client_id, :resource_identifier])
      |> Keyword.values()
      |> Enum.all?(&(byte_size(&1 || <<>>) > 0))
    else
      false
    end
  end
end
