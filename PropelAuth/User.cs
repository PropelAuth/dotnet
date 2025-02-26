using System.Security.Claims;
using Newtonsoft.Json;

namespace PropelAuth.Models
{
    /// <summary>
    /// Represents an authenticated user with their associated information and organization memberships.
    /// </summary>
    public class User
    {
        #region Properties

        // Public properties
        public string UserId { get; }
        public string Email { get; }
        public string? FirstName { get; }
        public string? LastName { get; }
        public string? Username { get; }
        public string? LegacyUserId { get; }
        public LoginMethod LoginMethod { get; }
        public string? ImpersonatorUserId { get; }
        public Dictionary<string, object>? Properties { get; }

        // Private properties
        private Dictionary<string, OrgMemberInfo>? OrgIdToOrgMemberInfo { get; set; }
        private string? ActiveOrgId { get; set; }

        #endregion

        #region Constructor

        /// <summary>
        /// Creates a user from claims principal data.
        /// </summary>
        /// <param name="claimsPrincipal">The claims principal containing user information.</param>
        public User(ClaimsPrincipal claimsPrincipal)
        {
            UserId = ExtractUserId(claimsPrincipal);
            Email = ExtractEmail(claimsPrincipal);
            FirstName = claimsPrincipal.FindFirstValue("first_name");
            LastName = claimsPrincipal.FindFirstValue("last_name");
            Username = claimsPrincipal.FindFirstValue("username");
            LegacyUserId = claimsPrincipal.FindFirstValue("legacy_user_id");
            ImpersonatorUserId = claimsPrincipal.FindFirstValue("impersonator_user_id");

            ProcessOrgInformation(claimsPrincipal);
            Properties = ParseUserProperties(claimsPrincipal);
            LoginMethod = ParseLoginMethodFromClaims(claimsPrincipal);
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Checks if the user has the specified role in the given organization.
        /// </summary>
        public bool IsRoleInOrg(string orgId, string role)
        {
            var org = GetOrg(orgId);
            return org?.IsRole(role) ?? false;
        }

        /// <summary>
        /// Checks if the user has at least the specified role in the given organization.
        /// </summary>
        public bool IsAtLeastRoleInOrg(string orgId, string role)
        {
            var org = GetOrg(orgId);
            return org?.IsAtLeastRole(role) ?? false;
        }

        /// <summary>
        /// Checks if the user has the specified permission in the given organization.
        /// </summary>
        public bool HasPermissionInOrg(string orgId, string permission)
        {
            var org = GetOrg(orgId);
            return org?.HasPermission(permission) ?? false;
        }

        /// <summary>
        /// Checks if the user has all specified permissions in the given organization.
        /// </summary>
        public bool HasAllPermissionsInOrg(string orgId, string[] permissions)
        {
            var org = GetOrg(orgId);
            return org?.HasAllPermissions(permissions) ?? false;
        }

        /// <summary>
        /// Gets all organizations the user is a member of.
        /// </summary>
        public OrgMemberInfo[] GetOrgs()
        {
            if (OrgIdToOrgMemberInfo == null)
            {
                return Array.Empty<OrgMemberInfo>();
            }

            return OrgIdToOrgMemberInfo.Values.ToArray();
        }

        /// <summary>
        /// Checks if the user is being impersonated.
        /// </summary>
        public bool IsImpersonated() => !string.IsNullOrEmpty(ImpersonatorUserId);

        /// <summary>
        /// Gets the organization information for the specified organization ID.
        /// </summary>
        public OrgMemberInfo? GetOrg(string orgId)
        {
            if (OrgIdToOrgMemberInfo != null && OrgIdToOrgMemberInfo.TryGetValue(orgId, out var orgInfo))
            {
                return orgInfo;
            }

            return null;
        }

        /// <summary>
        /// Gets a user property by name.
        /// </summary>
        public object? GetUserProperty(string propertyName)
        {
            if (Properties != null && Properties.TryGetValue(propertyName, out var value))
            {
                return value;
            }

            return null;
        }

        /// <summary>
        /// Gets the user's active organization information.
        /// </summary>
        public OrgMemberInfo? GetActiveOrg()
        {
            if (string.IsNullOrEmpty(ActiveOrgId) || OrgIdToOrgMemberInfo == null)
            {
                return null;
            }

            if (OrgIdToOrgMemberInfo.TryGetValue(ActiveOrgId, out var activeOrgInfo))
            {
                return activeOrgInfo;
            }

            return null;
        }

        /// <summary>
        /// Gets the user's active organization ID.
        /// </summary>
        public string? GetActiveOrgId() => ActiveOrgId;

        #endregion

        #region Private Methods

        private string ExtractUserId(ClaimsPrincipal claimsPrincipal)
        {
            string? userId = claimsPrincipal.FindFirstValue("user_id");
            if (string.IsNullOrEmpty(userId))
            {
                throw new ArgumentException("Required claim 'user_id' is missing or empty", nameof(claimsPrincipal));
            }

            return userId;
        }

        private string ExtractEmail(ClaimsPrincipal claimsPrincipal)
        {
            string? email = claimsPrincipal.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrEmpty(email))
            {
                throw new ArgumentException($"Required claim '{ClaimTypes.Email}' is missing or empty", nameof(claimsPrincipal));
            }

            return email;
        }
        
        /// <summary>
        /// Processes organization information from claims.
        /// </summary>
        private void ProcessOrgInformation(ClaimsPrincipal claimsPrincipal)
        {
            var orgsClaim = claimsPrincipal.FindFirst("org_id_to_org_member_info") ??
                            claimsPrincipal.FindFirst("org_member_info");

            if (orgsClaim == null) return;

            if (orgsClaim.Type == "org_id_to_org_member_info")
            {
                OrgIdToOrgMemberInfo = JsonConvert.DeserializeObject<Dictionary<string, OrgMemberInfo>>(orgsClaim.Value);
            }
            else
            {
                var orgInfo = JsonConvert.DeserializeObject<OrgMemberInfo>(orgsClaim.Value);
                if (orgInfo != null)
                {
                    OrgIdToOrgMemberInfo = new Dictionary<string, OrgMemberInfo>
                    {
                        {orgInfo.OrgId, orgInfo}
                    };
                    ActiveOrgId = orgInfo.OrgId;
                }
            }
        }

        /// <summary>
        /// Processes user properties from claims.
        /// </summary>
        private Dictionary<string, object>? ParseUserProperties(ClaimsPrincipal claimsPrincipal)
        {
            var propertiesClaim = claimsPrincipal.FindFirst("properties");
            return propertiesClaim != null ? JsonConvert.DeserializeObject<Dictionary<string, object>>(propertiesClaim.Value) : null;
        }

        /// <summary>
        /// Parses login method from claims.
        /// </summary>
        private LoginMethod ParseLoginMethodFromClaims(ClaimsPrincipal claimsPrincipal)
        {
            var loginMethodClaim = claimsPrincipal.FindFirst("login_method");
            if (loginMethodClaim == null)
            {
                return LoginMethod.Unknown();
            }

            return ParseLoginMethod(loginMethodClaim.Value);
        }

        /// <summary>
        /// Parses login method from a JSON string.
        /// </summary>
        private static LoginMethod ParseLoginMethod(string loginMethodString)
        {
            var loginMethodData = JsonConvert.DeserializeObject<Dictionary<string, string>>(loginMethodString);

            if (loginMethodData == null || !loginMethodData.TryGetValue("login_method", out var type))
            {
                return LoginMethod.Unknown();
            }

            return type switch
            {
                "password" => LoginMethod.Password(),
                "magic_link" => LoginMethod.MagicLink(),
                "social_sso" => CreateSocialSsoLoginMethod(loginMethodData),
                "email_confirmation_link" => LoginMethod.EmailConfirmationLink(),
                "saml_sso" => CreateSamlSsoLoginMethod(loginMethodData),
                "impersonation" => LoginMethod.Impersonation(),
                "generated_from_backend_api" => LoginMethod.GeneratedFromBackendApi(),
                _ => LoginMethod.Unknown()
            };
        }

        /// <summary>
        /// Creates a Social SSO login method.
        /// </summary>
        private static LoginMethod CreateSocialSsoLoginMethod(Dictionary<string, string> loginMethodData)
        {
            var provider = loginMethodData.TryGetValue("provider", out var socialProvider)
                ? socialProvider
                : "unknown";
            return LoginMethod.SocialSso(provider);
        }

        /// <summary>
        /// Creates a SAML SSO login method.
        /// </summary>
        private static LoginMethod CreateSamlSsoLoginMethod(Dictionary<string, string> loginMethodData)
        {
            var samlProvider = loginMethodData.TryGetValue("provider", out var samlProviderValue)
                ? samlProviderValue
                : "unknown";
            var orgId = loginMethodData.TryGetValue("org_id", out var orgIdValue) 
                ? orgIdValue 
                : "unknown";
            return LoginMethod.SamlSso(samlProvider, orgId);
        }

        #endregion
    }

    /// <summary>
    /// Extension methods for ClaimsPrincipal to work with PropelAuth users.
    /// </summary>
    public static class ClaimsPrincipalExtensions
    {
        /// <summary>
        /// Gets a PropelAuth User from a ClaimsPrincipal.
        /// </summary>
        public static User GetUser(this ClaimsPrincipal claimsPrincipal) => new(claimsPrincipal);
    }
}