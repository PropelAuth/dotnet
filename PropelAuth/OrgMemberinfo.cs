using Newtonsoft.Json;

namespace PropelAuth.Models
{
    /// <summary>
    /// Represents information about a user's membership in an organization.
    /// </summary>
    public class OrgMemberInfo
    {
        #region Properties

        /// <summary>
        /// Gets the unique identifier of the organization.
        /// </summary>
        [JsonProperty("org_id")]
        public string OrgId { get; }

        /// <summary>
        /// Gets the display name of the organization.
        /// </summary>
        [JsonProperty("org_name")]
        public string OrgName { get; }

        /// <summary>
        /// Gets the URL-safe version of the organization name.
        /// </summary>
        [JsonProperty("url_safe_org_name")]
        public string UrlSafeOrgName { get; }

        /// <summary>
        /// Gets the legacy identifier of the organization, if any.
        /// </summary>
        [JsonProperty("legacy_org_id")]
        public string LegacyOrgId { get; }

        /// <summary>
        /// Gets the metadata associated with the organization.
        /// </summary>
        [JsonProperty("org_metadata")]
        public Dictionary<string, object>? OrgMetadata { get; }

        /// <summary>
        /// Gets the user's primary role in the organization.
        /// </summary>
        [JsonProperty("user_role")]
        public string UserRole { get; }

        /// <summary>
        /// Gets all roles the user has in the organization, including inherited roles.
        /// </summary>
        [JsonProperty("inherited_user_roles_plus_current_role")]
        public IReadOnlyList<string> InheritedUserRolesPlusCurrentRole { get; }

        /// <summary>
        /// Gets the role structure of the organization.
        /// </summary>
        [JsonProperty("org_role_structure")]
        public string OrgRoleStructure { get; }

        /// <summary>
        /// Gets any additional roles the user has in the organization.
        /// </summary>
        [JsonProperty("additional_roles")]
        public IReadOnlyList<string>? AdditionalRoles { get; }

        /// <summary>
        /// Gets the permissions the user has in the organization.
        /// </summary>
        [JsonProperty("user_permissions")]
        public IReadOnlyList<string>? UserPermissions { get; }

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the <see cref="OrgMemberInfo"/> class.
        /// This constructor is used by JSON deserialization.
        /// </summary>
        [JsonConstructor]
        public OrgMemberInfo(
            string org_id,
            string org_name,
            string url_safe_org_name,
            string legacy_org_id,
            Dictionary<string, object>? org_metadata,
            string user_role,
            List<string> inherited_user_roles_plus_current_role,
            string org_role_structure,
            List<string>? additional_roles,
            List<string>? user_permissions)
        {
            OrgId = org_id;
            OrgName = org_name;
            UrlSafeOrgName = url_safe_org_name;
            LegacyOrgId = legacy_org_id;
            OrgMetadata = org_metadata;
            UserRole = user_role;
            InheritedUserRolesPlusCurrentRole = inherited_user_roles_plus_current_role?.AsReadOnly() ?? new List<string>().AsReadOnly();
            OrgRoleStructure = org_role_structure;
            AdditionalRoles = additional_roles?.AsReadOnly();
            UserPermissions = user_permissions?.AsReadOnly();
        }

        #endregion

        #region Methods

        /// <summary>
        /// Determines whether the user has the specified role in the organization.
        /// </summary>
        /// <param name="role">The role to check.</param>
        /// <returns>True if the user has the exact role; otherwise, false.</returns>
        public bool IsRole(string role)
        {
            return UserRole == role;
        }

        /// <summary>
        /// Determines whether the user has at least the specified role in the organization.
        /// </summary>
        /// <param name="role">The minimum role to check.</param>
        /// <returns>True if the user has the specified role or a role that inherits it; otherwise, false.</returns>
        public bool IsAtLeastRole(string role)
        {
            return UserRole == role || InheritedUserRolesPlusCurrentRole.Contains(role);
        }

        /// <summary>
        /// Determines whether the user has the specified permission in the organization.
        /// </summary>
        /// <param name="permission">The permission to check.</param>
        /// <returns>True if the user has the permission; otherwise, false.</returns>
        public bool HasPermission(string permission)
        {
            return UserPermissions != null && UserPermissions.Contains(permission);
        }

        /// <summary>
        /// Determines whether the user has all of the specified permissions in the organization.
        /// </summary>
        /// <param name="permissions">The permissions to check.</param>
        /// <returns>True if the user has all of the specified permissions; otherwise, false.</returns>
        public bool HasAllPermissions(string[] permissions)
        {
            if (UserPermissions == null)
            {
                return false;
            }
            
            return permissions.All(permission => UserPermissions.Contains(permission));
        }

        #endregion
    }
}