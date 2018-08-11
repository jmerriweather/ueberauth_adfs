# Ueberauth ADFS

## Installation

The package can be installed by adding `ueberauth_adfs` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ueberauth_adfs, "~> 0.2.0"}
  ]
end
```

Docs can be found at [https://hexdocs.pm/ueberauth_adfs](https://hexdocs.pm/ueberauth_adfs).

## Setting up ADFS

#### In ADFS >=3.0 setup a new Client using Powershell:
  ```
  Add-AdfsClient -Name "OAUTH2 Client" -ClientId "unique-custom-client-id" -RedirectUri "http://localhost:4000/auth/adfs/callback"
  Add-ADFSRelyingPartyTrust -Name "OAUTH2 Client" -Identifier "http://localhost:4000/auth/adfs"
  Set-AdfsRelyingPartyTrust -IssuanceAuthorizationRulesFile "TransformRules.txt"
  ```
#### In TransformRules.txt put the following:
  ```
  @RuleTemplate = "LdapClaims"
  @RuleName = "User Details"
  c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "groups", "userPrincipalName"), query = ";sAMAccountName,givenName,sn,mail,tokenGroups,userPrincipalName;{0}", param = c.Value);
  ```

## Configuring Application

#### Add `adfs_url` and `client_id` to your configuration:
  ```elixir
  config :ueberauth, Ueberauth.Strategy.ADFS.OAuth,
    adfs_url: System.get_env("ADFS_URL"),
    adfs_metadata_url: System.get_env("ADFS_METADATA_URL"),
    adfs_handler: Ueberauth.Strategy.ADFS.DefaultHandler, # Optional, ability to provide handler to extract information from the token claims
    client_id: System.get_env("ADFS_CLIENT_ID"),
    resource_identifier: System.get_env("RESOURCE_IDENTIFIER")
  ```

#### Add ADFS provider to Ueberauth:
  ```elixir
  config :ueberauth, Ueberauth,
  providers: [
    adfs: { Ueberauth.Strategy.ADFS,
      [
        #uid_field: :email,
        #request_path: "/auth/adfs",
        #callback_path: "/auth/adfs/callback"
      ]
    }
  ]
  ```
