defmodule Ueberauth.Strategy.ADFSTest do
  use ExUnit.Case
  use Ueberauth.Strategy

  import Mock

  alias Ueberauth.Strategy.ADFS

  @env_values adfs_url: "https://example.com",
              adfs_metadata_url: "https://example.com/metadata.xml",
              client_id: "example_client",
              resource_identifier: "example_resource"

  @mock_metadata {:ok,
                  %HTTPoison.Response{
                    body:
                      "<EntityDescriptor><ds:Signature><KeyInfo>" <>
                        "<X509Data><X509Certificate>1234</X509Certificate></X509Data>" <>
                        "</KeyInfo></ds:Signature></EntityDescriptor>"
                  }}

  @user_claim %Joken.Token{
    claims: %{
      "email" => "user@test.com",
      "given_name" => "John",
      "family_name" => "Doe",
      "winaccountname" => "john1"
    }
  }

  describe "ADFS Strategy" do
    setup_with_mocks [
      {ADFS.OAuth, [:passthrough],
       [get_token: fn code, _ -> {:ok, %{token: %{access_token: code}}} end]},
      {Application, [:passthrough], [get_env: fn _, _ -> @env_values end]},
      {HTTPoison, [:passthrough], [get: fn _, _, _ -> @mock_metadata end]},
      {Joken, [:passthrough],
       [token: fn _ -> nil end, with_signer: fn _, _ -> nil end, verify: fn _ -> @user_claim end]},
      {JOSE.JWK, [:passthrough], [from_pem: fn _ -> %{foo: :bar} end]},
      {Ueberauth.Strategy.Helpers, [:passthrough],
       [
         callback_url: fn _ -> "https://test.com" end,
         options: fn _ -> [uid_field: "email"] end,
         redirect!: fn _conn, auth_url -> auth_url end,
         set_errors!: fn _conn, errors -> errors end
       ]}
    ] do
      :ok
    end

    test "Handles the ADFS request" do
      request = ADFS.handle_request!(%Plug.Conn{params: %{}})

      assert request =~ "#{@env_values[:adfs_url]}/adfs/oauth2/authorize"
    end

    test "Redirects ADFS request to index when missing config" do
      with_mock Application, [:passthrough], get_env: fn _, _ -> nil end do
        assert ADFS.handle_request!(nil) == "/"
      end
    end

    test "Handles the logout request" do
      assert ADFS.logout(nil, nil) =~ "#{@env_values[:adfs_url]}/adfs/ls/?wa=wsignout1.0"
    end

    test "Gives an error upon logout request with missing config" do
      with_mock Application, [:passthrough], get_env: fn _, _ -> nil end do
        assert ADFS.logout(nil, nil) == [
                 %Ueberauth.Failure.Error{
                   message: "Failed to logout, please close your browser",
                   message_key: "Logout Failed"
                 }
               ]
      end
    end

    test "Handle callback from ADFS provider, set claims user from JWT" do
      conn = ADFS.handle_callback!(%Plug.Conn{params: %{"code" => "1234"}})
      assert conn.private.adfs_user == @user_claim.claims
    end

    test "Handle callback from ADFS provider when JWT is unauthorized" do
      with_mock Joken,
                [:passthrough],
                token: fn _ -> nil end,
                with_signer: fn _, _ -> nil end,
                verify: fn _ -> nil end do
        [error] = ADFS.handle_callback!(%Plug.Conn{params: %{"code" => "1234"}})

        assert error ==
                 %Ueberauth.Failure.Error{
                   message: "unauthorized",
                   message_key: "token"
                 }
      end
    end

    test "Handle callback from ADFS provider when metadata is malformed" do
      with_mock HTTPoison,
                [:passthrough],
                get: fn _, _, _ -> {:ok, %HTTPoison.Response{body: ""}} end do
        [error] = ADFS.handle_callback!(%Plug.Conn{params: %{"code" => "1234"}})
        assert error == %Ueberauth.Failure.Error{message: "malformed", message_key: "metadata"}
      end
    end

    test "Handle callback from ADFS provider when certificate is not found in metadata" do
      with_mock HTTPoison, [:passthrough],
        get: fn _, _, _ ->
          {:ok, %HTTPoison.Response{body: "<EntityDescriptor></EntityDescriptor>"}}
        end do
        [error] = ADFS.handle_callback!(%Plug.Conn{params: %{"code" => "1234"}})
        assert error == %Ueberauth.Failure.Error{message: "not_found", message_key: "certificate"}
      end
    end

    test "Handle callback from ADFS provider when metadata url is not found" do
      with_mock HTTPoison,
                [:passthrough],
                get: fn _, _, _ -> {:error, %HTTPoison.Error{}} end do
        [error] = ADFS.handle_callback!(%Plug.Conn{params: %{"code" => "1234"}})

        assert error == %Ueberauth.Failure.Error{
                 message: "not_found",
                 message_key: "metadata_url"
               }
      end
    end

    test "Handle callback from ADFS provider with token error" do
      with_mock ADFS.OAuth,
                [:passthrough],
                get_token: fn _, _ -> {:error, %{reason: "token_error"}} end do
        [error] = ADFS.handle_callback!(%Plug.Conn{params: %{"code" => "1234"}})

        assert error == %Ueberauth.Failure.Error{
                 message: "token_error",
                 message_key: "Authentication Error"
               }
      end
    end

    test "Handle callback from ADFS provider with OAuth2 error" do
      with_mock ADFS.OAuth, [:passthrough],
        get_token: fn _, _ ->
          {:error, %OAuth2.Response{body: %{"error_description" => "oauth_error"}}}
        end do
        [error] = ADFS.handle_callback!(%Plug.Conn{params: %{"code" => "1234"}})

        assert error == %Ueberauth.Failure.Error{
                 message: "oauth_error",
                 message_key: "Authentication Error"
               }
      end
    end

    test "Handle callback from ADFS provider with error in the params" do
      [error] =
        ADFS.handle_callback!(%Plug.Conn{
          params: %{"error" => "param_error", "error_description" => "param_error_description"}
        })

      assert error == %Ueberauth.Failure.Error{
               message: "param_error_description",
               message_key: "param_error"
             }
    end

    test "Handle callback from ADFS provider with missing code" do
      [error] = ADFS.handle_callback!(%Plug.Conn{})

      assert error == %Ueberauth.Failure.Error{
               message: "No code received",
               message_key: "missing_code"
             }
    end

    test "Handles cleanup of the private vars in the conn" do
      conn =
        %Plug.Conn{params: %{"code" => "1234"}}
        |> ADFS.handle_callback!()
        |> ADFS.handle_cleanup!()

      assert conn.private.adfs_user == nil
      assert conn.private.adfs_token == nil
    end

    test "Gets the uid field from the conn" do
      email =
        %Plug.Conn{params: %{"code" => "1234"}}
        |> ADFS.handle_callback!()
        |> ADFS.uid()

      assert email == "user@test.com"
    end

    test "Gets the token credentials from the conn" do
      token =
        %Plug.Conn{params: %{"code" => "1234"}}
        |> ADFS.handle_callback!()
        |> ADFS.credentials()

      assert token == %Ueberauth.Auth.Credentials{}
    end

    test "Gets the user info from the conn" do
      info =
        %Plug.Conn{params: %{"code" => "1234"}}
        |> ADFS.handle_callback!()
        |> ADFS.info()

      assert info == %Ueberauth.Auth.Info{
               name: "John Doe",
               nickname: "john1",
               email: "user@test.com"
             }
    end

    test "Gets the extra info from the conn" do
      extra =
        %Plug.Conn{params: %{"code" => "1234"}}
        |> ADFS.handle_callback!()
        |> ADFS.extra()

      assert %Ueberauth.Auth.Extra{raw_info: %{token: %Joken.Token{}, user: %{}}} = extra
    end

    test "Returns the configured status when env is present" do
      assert ADFS.configured?() == true
    end

    test "Returns the configured status when env is not present" do
      with_mock Application, [:passthrough], get_env: fn _, _ -> nil end do
        assert ADFS.configured?() == false
      end
    end

    test "Returns the configured status when env is missing values" do
      with_mock Application,
                [:passthrough],
                get_env: fn _, _ -> [adfs_url: "https://test.com"] end do
        assert ADFS.configured?() == false
      end
    end
  end

  describe "ADFS Oauth Client" do
    setup_with_mocks [{Application, [:passthrough], [get_env: fn _, _ -> @env_values end]}] do
      :ok
    end

    test "Gets the client with the config properties" do
      client = ADFS.OAuth.client()

      assert client.client_id == @env_values[:client_id]
      assert client.authorize_url == "#{@env_values[:adfs_url]}/adfs/oauth2/authorize"
      assert client.token_url == "#{@env_values[:adfs_url]}/adfs/oauth2/token"
    end

    test "Gets the client with options" do
      client = ADFS.OAuth.client(client_id: "other_client")
      assert client.client_id == "other_client"
    end

    test "Doesn't get the client without config" do
      with_mock Application, [:passthrough], get_env: fn _, _ -> nil end do
        client = ADFS.OAuth.client()

        assert client == {nil, []}
      end
    end

    test "Get the authorize_url" do
      assert ADFS.OAuth.authorize_url!() ==
               "#{@env_values[:adfs_url]}/adfs/oauth2/authorize?client_id=example_client&redirect_uri=&response_type=code"
    end

    test "Gets the signout url" do
      assert ADFS.OAuth.signout_url() ==
               {:ok, "#{@env_values[:adfs_url]}/adfs/ls/?wa=wsignout1.0"}
    end

    test "Gets the signout url with params" do
      assert ADFS.OAuth.signout_url(%{redirect_uri: "https://test.com"}) ==
               {:ok, "#{@env_values[:adfs_url]}/adfs/ls/?wa=wsignout1.0&wreply=https://test.com"}
    end

    test "Fails to get the signout url without config" do
      with_mock Application, [:passthrough], get_env: fn _, _ -> nil end do
        assert ADFS.OAuth.signout_url() == {:error, :failed_to_logout}
      end
    end
  end
end
