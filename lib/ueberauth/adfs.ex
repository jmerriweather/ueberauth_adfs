defmodule Ueberauth.Strategy.ADFS do
  import SweetXml

  use Ueberauth.Strategy,
    adfs_metadata_url: "https://path.to/FederationMetadata.xml",
    resource_identifier: "unknown",
    uid_field: "sid"

  alias Ueberauth.Auth.{Info, Credentials, Extra}
  alias Ueberauth.Strategy.ADFS.OAuth

  @doc """
  Handles initial request for ADFS authentication.
  """
  def handle_request!(conn) do
    authorize_url =
      conn.params
      |> Map.put(:resource, option(conn, :resource_identifier))
      |> Map.put(:redirect_uri, callback_url(conn))
      |> OAuth.authorize_url!()

    redirect!(conn, authorize_url)
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

  @doc """
  Handles the callback from ADFS.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    opts = [redirect_uri: callback_url(conn)]

    with {:ok, client} <- OAuth.send_token_request([code: code], opts) do
      fetch_user(conn, client)
    else
      {:error, %{reason: reason}} ->
        set_errors!(conn, [error("Authentication Error", reason)])

      {:error, %OAuth2.Response{body: %{"error_description" => reason}}} ->
        set_errors!(conn, [error("Authentication Error", reason)])
    end
  end

  @doc """
  Handles error callback from ADFS.
  """
  def handle_callback!(
        %Plug.Conn{params: %{"error" => error, "error_description" => error_description}} = conn
      ) do
    set_errors!(conn, [error(error, error_description)])
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:adfs_token, nil)
    |> put_private(:adfs_claims, nil)
  end

  def uid(conn) do
    user =
      conn
      |> option(:uid_field)
      |> to_string

    conn.private.adfs_claims[user]
  end

  def credentials(conn) do
    token = conn.private.adfs_token

    %Credentials{
      expires: token.claims["exp"] != nil,
      expires_at: token.claims["exp"],
      scopes: token.claims["aud"],
      token: token.token
      # token_type: token.token_type
    }
  end

  def info(conn) do
    claims = conn.private.adfs_claims

    %Info{
      nickname: claims["winaccountname"],
      name: "#{claims["given_name"]} #{claims["family_name"]}",
      email: claims["email"],
      first_name: claims["given_name"],
      last_name: claims["family_name"]
    }
  end

  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.adfs_token,
        claims: conn.private.adfs_claims,
        groups: conn.private.adfs_claims["groups"]
      }
    }
  end

  defp fetch_user(conn, %{token: %{access_token: access_token}}) do
    url = option(conn, :adfs_metadata_url)

    with {:ok, %HTTPoison.Response{body: metadata}} <-
           HTTPoison.get(url, [], ssl: [versions: [:"tlsv1.2"]]),
         true <- String.starts_with?(metadata, "<EntityDescriptor"),
         {:ok, certificate} <- cert_from_metadata(metadata) do
      key =
        certificate
        |> JOSE.JWK.from_pem()
        |> Joken.rs256()

      # TODO: Peek header and check algo
      jwt =
        access_token
        |> Joken.token()
        |> Joken.with_signer(key)
        |> Joken.verify()

      conn = put_private(conn, :adfs_token, jwt)

      with %Joken.Token{claims: claims} <- jwt do
        put_private(conn, :adfs_claims, claims)
      else
        _ -> set_errors!(conn, [error("token", "unauthorized")])
      end
    else
      {:error, :metadata_not_found} -> set_errors!(conn, [error("metadata", "not_found")])
      {:error, :cert_not_found} -> set_errors!(conn, [error("certificate", "not_found")])
      _ -> set_errors!(conn, [error("metadata", "unkown")])
    end
  end

  defp cert_from_metadata(metadata) when is_binary(metadata) do
    metadata
    |> xpath(~x"//EntityDescriptor/ds:Signature/KeyInfo/X509Data/X509Certificate/text()")
    |> build_cert()
  end

  defp cert_from_metadata(_), do: {:error, :metadata_not_found}

  defp build_cert(cert_content) when is_binary(cert_content) do
    {:ok,
     """
     -----BEGIN CERTIFICATE-----
     #{cert_content}
     -----END CERTIFICATE-----
     """}
  end

  defp build_cert(_), do: {:error, :cert_not_found}

  defp option(conn, key) do
    default = Keyword.get(default_options(), key)

    conn
    |> options
    |> Keyword.get(key, default)
  end
end
