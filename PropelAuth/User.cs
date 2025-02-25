using System.Security.Claims;
using Newtonsoft.Json;

namespace PropelAuth.Models
{
    public class User
    {
        public string userId { get; set; }
        public string email { get; set; }
        public string? firstName { get; set; }
        public string? lastName { get; set; }
        public string? username { get; set; }

        public string? legacyUserId { get; set; }

        public string? impersonatorUserId { get; set; }
        public Dictionary<string, OrgMemberInfo>? orgIdToOrgMemberInfo { get; set; }
        public Dictionary<string, object>? properties { get; set; }
        public LoginMethod loginMethod { get; set; }
        public string? activeOrgId { get; set; }

        public User(ClaimsPrincipal claimsPrincipal)
        {
            userId = claimsPrincipal.FindFirstValue("user_id");
            email = claimsPrincipal.FindFirstValue(ClaimTypes.Email);
            firstName = claimsPrincipal.FindFirstValue("first_name");
            lastName = claimsPrincipal.FindFirstValue("last_name");
            username = claimsPrincipal.FindFirstValue("username");
            legacyUserId = claimsPrincipal.FindFirstValue("legacy_user_id");
            impersonatorUserId = claimsPrincipal.FindFirstValue("impersonator_user_id");

            var orgsClaim = claimsPrincipal.FindFirst("org_id_to_org_member_info") ?? claimsPrincipal.FindFirst("org_member_info");
            if (orgsClaim != null)
            {
                if (orgsClaim.Type == "org_id_to_org_member_info")
                {
                    orgIdToOrgMemberInfo = JsonConvert.DeserializeObject<Dictionary<string, OrgMemberInfo>>(orgsClaim.Value);
                }
                else {
                    var orgInfo = JsonConvert.DeserializeObject<OrgMemberInfo>(orgsClaim.Value);
                    if (orgInfo != null) {
                        orgIdToOrgMemberInfo = new Dictionary<string, OrgMemberInfo> {
                        { orgInfo.orgId ?? "", orgInfo }
                    };
                        activeOrgId = orgInfo.orgId;
                    }
                }
            }

            var propertiesClaim = claimsPrincipal.FindFirst("properties");
            if (propertiesClaim != null)
            {
                properties = JsonConvert.DeserializeObject<Dictionary<string, object>>(propertiesClaim.Value);
            }

            var loginMethodClaim = claimsPrincipal.FindFirst("login_method");
            if (loginMethodClaim != null)
            {
                loginMethod = ParseLoginMethod(loginMethodClaim.Value);
            }
            else
            {
                loginMethod = LoginMethod.Unknown();
            }

            LoginMethod ParseLoginMethod(string loginMethodString)
            {
                var loginMethodData = JsonConvert.DeserializeObject<Dictionary<string, string>>(loginMethodString);

                if (loginMethodData == null || !loginMethodData.TryGetValue("login_method", out var type))
                {
                    return LoginMethod.Unknown();
                }

                switch (type)
                {
                    case "password":
                        return LoginMethod.Password();
                    case "magic_link":
                        return LoginMethod.MagicLink();
                    case "social_sso":
                        var provider = loginMethodData.TryGetValue("provider", out var socialProvider) ? socialProvider : "unknown";
                        return LoginMethod.SocialSso(provider);
                    case "email_confirmation_link":
                        return LoginMethod.EmailConfirmationLink();
                    case "saml_sso":
                        var samlProvider = loginMethodData.TryGetValue("provider", out var samlProviderValue) ? samlProviderValue : "unknown";
                        var orgId = loginMethodData.TryGetValue("org_id", out var orgIdValue) ? orgIdValue : "unknown";
                        return LoginMethod.SamlSso(samlProvider, orgId);
                    case "impersonation":
                        return LoginMethod.Impersonation();
                    case "generated_from_backend_api":
                        return LoginMethod.GeneratedFromBackendApi();
                    default:
                        return LoginMethod.Unknown();
                }
            }


        }

        public bool IsRoleInOrg(string orgId, string role)
        {
            var org = GetOrg(orgId);
            return org?.IsRole(role) ?? false;
        }

        public bool IsAtLeastRoleInOrg(string orgId, string role)
        {
            var org = GetOrg(orgId);
            return org?.IsAtLeastRole(role) ?? false;
        }

        public bool HasPermissionInOrg(string orgId, string permission)
        {
            var org = GetOrg(orgId);
            return org?.HasPermission(permission) ?? false;
        }

        public bool HasAllPermissionsInOrg(string orgId, string[] permissions)
        {
            var org = GetOrg(orgId);
            return org?.HasAllPermissions(permissions) ?? false;
        }

        public OrgMemberInfo[] GetOrgs()
        {
            if (orgIdToOrgMemberInfo == null)
            {
                return Array.Empty<OrgMemberInfo>();
            }
            return orgIdToOrgMemberInfo.Values.ToArray();
        }

        public bool IsImpersonated()
        {
            return !string.IsNullOrEmpty(impersonatorUserId);
        }

        public OrgMemberInfo? GetOrg(string orgId)
        {
            if (orgIdToOrgMemberInfo != null && orgIdToOrgMemberInfo.TryGetValue(orgId, out var orgInfo))
            {
                return orgInfo;
            }
            return null;
        }

        public object? GetUserProperty(string propertyName)
        {
            if (properties != null && properties.TryGetValue(propertyName, out var value))
            {
                return value;
            }
            return null;
        }

        public OrgMemberInfo? GetActiveOrg()
        {
            if (string.IsNullOrEmpty(activeOrgId) || orgIdToOrgMemberInfo == null)
            {
                return null;
            }

            if (orgIdToOrgMemberInfo.TryGetValue(activeOrgId, out var activeOrgInfo))
            {
                return activeOrgInfo;
            }
            return null;
        }

        public string? GetActiveOrgId()
        {
            return activeOrgId;
        }

    }

    public static class ClaimsPrincipalExtensions
    {
        public static User GetUser(this ClaimsPrincipal claimsPrincipal)
        {
            return new User(claimsPrincipal);
        }
    }


}
