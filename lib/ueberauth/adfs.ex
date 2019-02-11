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
          id_token: conn.private[:adfs_id_token],
          user: user,
          groups: user["groups"]
        }
      }
    end
  end
  ```
  """
  require Logger

  use Ueberauth.Strategy

  alias Ueberauth.Strategy.ADFS.OAuth

  def handle_request!(conn) do
    if __MODULE__.configured?() do
      jason_lib = config(:json_library)

      if jason_lib do
        Application.put_env(:oauth2, :serializers, %{"application/json" => jason_lib})
        JOSE.json_module(jason_lib)
      end

      redirect_to_authorization(conn)
    else
      redirect!(conn, "/")
    end
  end

  def logout(conn, id_token) do
    params = %{redirect_uri: callback_url(conn), id_token: id_token}

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
    |> put_private(:adfs_id_token, nil)
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

  def jason_module() do
    config(:json_library, Poison)
  end

  def get_wellknown_url() do
    config(:adfs_url)
    |> URI.merge("/adfs/.well-known/openid-configuration")
    |> URI.to_string()
  end

  defp check_and_set_json_module(data) do
    Joken.with_json_module(data, jason_module())
  end

  def make_token(payload) when is_map(payload) do
    %Joken.Token{claims: payload}
    |> check_and_set_json_module
  end

  def make_token(encoded_token) when is_binary(encoded_token) do
    %Joken.Token{token: encoded_token}
    |> check_and_set_json_module
  end

  defp fetch_user(conn, %{token: %{access_token: access_token} = token}) do
    # IO.puts("token: #{inspect token}")
    adfs_handler = config(:adfs_handler, Ueberauth.Strategy.ADFS.DefaultHandler)

    conn = put_private(conn, :adfs_handler, adfs_handler)

    conn =
      with {:ok, other} <- Map.fetch(token, :other_params),
           %{"id_token" => id_token} <- other,
           {:ok, validated_token} <- make_token(id_token) |> validate_token() do
        put_private(conn, :adfs_id_token, validated_token)
      else
        _ ->
          conn
      end

    conn =
      with made_token <- make_token(access_token),
           {:ok, validated_token} <- validate_token(made_token),
           %Joken.Token{claims: claims_user, error: nil} <- validated_token do
        conn
        |> put_private(:adfs_token, validated_token)
        |> put_private(:adfs_user, claims_user)
      else
        :token_not_verified ->
          Logger.error("#{inspect(__MODULE__)} - Token Validation Failed")
          set_errors!(conn, [error("token", "unauthorized")])

        %{error: "Invalid signature"} ->
          Logger.error("#{inspect(__MODULE__)} - Invalid Public Key")
          set_errors!(conn, [error("token", "unauthorized")])

        _ ->
          set_errors!(conn, [error("token", "unauthorized")])
      end

    # IO.puts("CONN: #{inspect conn}")
    conn
  end

  def validate_token(token = %Joken.Token{token: token_string}) do
    table_name =
      try do
        :ets.new(:adfs_keys_lookup, [:set, :public, :named_table])
      rescue
        _ -> :adfs_keys_lookup
      end

    with {:ok, decoded_header} <-
           String.split(token_string, ".") |> List.first() |> Base.decode64(),
         {:ok, %{"x5t" => identifier}} <- jason_module().decode(decoded_header),
         {:ok, key} <- lookup_key(table_name, identifier, :ets.lookup(table_name, identifier)),
         {:ok, certificate} <- build_cert(key) do
      rs256_key = JOSE.JWK.from_pem(certificate) |> Joken.rs256()
      {:ok, Joken.with_signer(token, rs256_key) |> Joken.verify()}
    else
      _ -> :token_not_verified
    end
  end

  def lookup_key(table, identifier, []) do
    update_key_cache(table)

    case :ets.lookup(table, identifier) do
      [] -> :no_valid_key
      [{^identifier, [certificate]}] -> {:ok, certificate}
    end
  end

  def lookup_key(_table, identifier, [{lookup_key, [certificate]}]) do
    if identifier === lookup_key do
      {:ok, certificate}
    else
      :no_valid_key
    end
  end

  def update_key_cache(table) do
    get_wellknown_url()
    |> keys_from_wellknown()
    |> Enum.each(fn %{"x5t" => identifier, "x5c" => certificate} ->
      :ets.insert(table, {identifier, certificate})
    end)
  end

  def keys_from_wellknown(well_known_url) do
    with {:ok, %HTTPoison.Response{body: wellknown}} <-
           HTTPoison.get(well_known_url, [], ssl: [versions: [:"tlsv1.2"]]),
         {:ok, %{"jwks_uri" => keys_url}} <- jason_module().decode(wellknown),
         {:ok, %HTTPoison.Response{body: keys_body}} <-
           HTTPoison.get(keys_url, [], ssl: [versions: [:"tlsv1.2"]]),
         {:ok, %{"keys" => keys}} <- jason_module().decode(keys_body) do
      keys
    else
      error ->
        IO.puts("Error: #{inspect(error)}")
        []
    end
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

  defp config(option, default \\ nil) do
    :ueberauth
    |> Application.get_env(__MODULE__)
    |> Keyword.get(option, default)
  end

  defp redirect_to_authorization(conn) do
    authorize_url =
      conn.params
      |> Map.put(:resource, config(:resource_identifier))
      |> Map.put(:redirect_uri, callback_url(conn))
      |> OAuth.authorize_url!()

    redirect!(conn, authorize_url)
  end

  defp env_present?(env) when not is_nil(env) do
    if Keyword.has_key?(env, :adfs_url) && Keyword.has_key?(env, :client_id) &&
         Keyword.has_key?(env, :resource_identifier) do
      env
      |> Keyword.take([:adfs_url, :client_id, :resource_identifier])
      |> Keyword.values()
      |> Enum.all?(&(byte_size(&1 || <<>>) > 0))
    else
      false
    end
  end

  defp env_present?(_), do: false
end
