<p align="center">
  <a href="https://www.propelauth.com?ref=github" target="_blank" align="center">
    <img src="https://www.propelauth.com/imgs/lockup.svg" width="200">
  </a>
</p>

# PropelAuth .NET Library

A .NET library for managing authentication, backed by [PropelAuth](https://www.propelauth.com?ref=github). 

[PropelAuth](https://www.propelauth.com?ref=github) makes it easy to add authentication and authorization to your B2B/multi-tenant application.

Your frontend gets a beautiful, safe, and customizable login screen. Your backend gets easy authorization with just a few lines of code. You get an easy-to-use dashboard to config and manage everything.

## Documentation

- Full reference this library is [here](https://docs.propelauth.com/reference/backend-apis/dot-net)
- Getting started guides for PropelAuth are [here](https://docs.propelauth.com/)

## Installation

```shell
dotnet add package PropelAuth
```
---

## Initialize

`AddPropelAuthAsync` performs a one-time initialization of the library. 
It will verify your `apiKey` is correct and fetch the metadata needed to verify access tokens in [GetUser](https://docs.propelauth.com/reference/backend-apis/dot-net#protect-api-routes).


```csharp
using System.Security.Claims;
using PropelAuth;
using PropelAuth.Models;

var builder = WebApplication.CreateBuilder(args);

await builder.Services.AddPropelAuthAsync(new PropelAuthOptions(
    apiKey: "YOUR_API_KEY",
    authUrl: "YOUR_AUTH_URL"
));
```

---

## Protect API Routes


The `PropelAuth` .NET library provides a User Class to validate the access token and provide the [user's information](https://docs.propelauth.com/reference/backend-apis/dot-net#user-class) if it is valid. To get the User Class, use the `GetUser()` method on the [ClaimsPrincipal](https://learn.microsoft.com/en-us/dotnet/api/system.security.claims.claimsprincipal?view=net-8.0) Class.

If the access token is not valid, the user's properties will be set to null. If that's the case, you can use .NET's [Results Class](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.results?view=aspnetcore-8.0) to return a `401 Unauthorized` error.

```csharp
app.MapGet("/", (ClaimsPrincipal claimsPrincipal) =>
{
    var user = claimsPrincipal.GetUser();
    if (user == null)
    {
        return Results.Unauthorized();
    }
    return Results.Ok($"Hello user with ID {user.userId}");
});
```

Verifying the access token doesn't require an external request.

## Authorization / Organizations

You can also verify which organizations the user is in, and which roles and permissions they have in each organization. 

### Check Org Membership

Verify that the request was made by a valid user **and** that the user is a member of the specified organization.

```csharp
app.MapGet("/api/org/{orgId}", (ClaimsPrincipal claimsPrincipal, string orgId) =>
{
    var user = claimsPrincipal.GetUser();
    if (user == null)
    {
        return Results.Unauthorized();
    }
    var org = user.GetOrg(orgId);
    if (org == null)
    {
        return Results.Forbid();
    }
    return Results.Ok($"You are in {org.orgName}");
});
```

### Check Org Membership and Role

Similar to checking org membership, but will also verify that the user has a specific Role in the organization.

A user has a Role within an organization. By default, the available roles are Owner, Admin, or Member, but these can be configured. These roles are also hierarchical, so Owner > Admin > Member.

```csharp
app.MapGet("/api/org/{orgId}", (ClaimsPrincipal claimsPrincipal, string orgId) =>
{
    var user = claimsPrincipal.GetUser();
    if (user == null)
    {
        return Results.Unauthorized();
    }
    var org = user.GetOrg(orgId);
    if (org != null && org.IsRole("Admin"))
    {
        return Results.Ok($"You are in {org.orgName}");
    }
    return Results.Forbid();
});
```

### Check Org Membership and Permission

Similar to checking org membership, but will also verify that the user has the specified permission in the organization.

Permissions are arbitrary strings associated with a role. For example, `can_view_billing`, `ProductA::CanCreate`, and `ReadOnly` are all valid permissions. You can create these permissions in the PropelAuth dashboard.

```csharp
app.MapGet("/api/org/{orgId}", (ClaimsPrincipal claimsPrincipal, string orgId) =>
{
    var user = claimsPrincipal.GetUser();
    if (user == null)
    {
        return Results.Unauthorized();
    }
    var org = user.GetOrg(orgId);
    if (org != null && org.HasPermission("can_view_billing"))
    {
        return Results.Ok($"You are allowed to view billing information for org {org.orgName}");
    }
    return Results.Forbid();
});
```

## Questions?

Feel free to reach out at support@propelauth.com
