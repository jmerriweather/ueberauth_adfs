defmodule Ueberauth.Strategy.ADFS do
  use Ueberauth.Strategy,
    adfs_signing_certificate: "priv/sign-certificate.pem",
    resource_identifier: "unknown"

  alias Ueberauth.Auth.{Info, Credentials, Extra}
  alias Ueberauth.Strategy.ADFS.OAuth

  @doc """
  Handles initial request for ADFS authentication.
  """
  def handle_request!(conn) do
    authorize_url = conn.params
      |> Map.put(:resource, option(conn, :resource_identifier))
      |> Map.put(:redirect_uri, callback_url(conn))
      |> OAuth.authorize_url!

    redirect!(conn, authorize_url)
  end

  @doc """
  Handles the callback from ADFS.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    opts = [redirect_uri: callback_url(conn)]

    client = OAuth.get_token!([code: code], opts)

    case client.token.access_token do
      "" ->
        err = client.token.other_params["error"]
        desc = client.token.other_params["error_description"]
        set_errors!(conn, [error(err, desc)])
      _token ->
        fetch_user(conn, client)
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
      |> put_private(:adfs_token, nil)
      |> put_private(:adfs_user, nil)
  end

  def uid(conn) do
    user = conn
      |> option(:uid_field)
      |> to_string

    conn.private.adfs_user[user]
  end

  def credentials(conn) do
    token = conn.private.adfs_token

    %Credentials{
      expires: token.claims["exp"] != nil,
      expires_at: token.claims["exp"],
      scopes: token.claims["aud"],
      token: token.token,
      #token_type: token.token_type
    }
  end

  def info(conn) do
    user = conn.private.adfs_user

    %Info{
      nickname: user["winaccountname"],
      name: "#{user["given_name"]} #{user["family_name"]}",
      email: user["email"],
      first_name: user["given_name"],
      last_name: user["family_name"]
    }
  end

  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.adfs_token,
        user: conn.private.adfs_user,
        groups: conn.private.adfs_user["groups"]
      }
    }
  end

  defp fetch_user(conn, %{token: %{access_token: access_token}}) do
    adfs_signing_certificate = option(conn, :adfs_signing_certificate)
    key = JOSE.JWK.from_pem_file(adfs_signing_certificate) |> Joken.rs256()

    # TODO: Peek header and check algo
    jwt = access_token
      |> Joken.token()
      |> Joken.with_signer(key)
      |> Joken.verify

    conn = put_private(conn, :adfs_token, jwt)

    with %Joken.Token{ claims: claims } <- jwt do
      put_private(conn, :adfs_user, claims)
    else
      _ -> set_errors!(conn, [error("token", "unauthorized")])
    end
  end

  defp option(conn, key) do
    default = Keyword.get(default_options(), key)

    conn
      |> options
      |> Keyword.get(key, default)
  end
end
