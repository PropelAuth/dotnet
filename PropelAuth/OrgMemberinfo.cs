using System.Collections.Generic;
using Newtonsoft.Json;

namespace PropelAuth.Models
{
    public class OrgMemberInfo
    {
        [JsonProperty("org_id")]
        public string orgId { get; set; }

        [JsonProperty("org_name")]
        public string orgName { get; set; }

        [JsonProperty("url_safe_org_name")]
        public string urlSafeOrgName { get; set; }

        [JsonProperty("org_metadata")]
        public Dictionary<string, object>? orgMetadata { get; set; }

        [JsonProperty("user_role")]
        public string userRole { get; set; }

        [JsonProperty("inherited_user_roles_plus_current_role")]
        public List<string> inheritedUserRolesPlusCurrentRole { get; set; }

        [JsonProperty("org_role_structure")]
        public string orgRoleStructure { get; set; }

        [JsonProperty("additional_roles")]
        public List<string>? additionalRoles { get; set; }

        [JsonProperty("user_permissions")]
        public List<string>? userPermissions { get; set; }

        public bool IsRole(string role)
        {
            return userRole == role;
        }
        public bool IsAtLeastRole(string role)
        {
            return userRole == role || (inheritedUserRolesPlusCurrentRole != null && inheritedUserRolesPlusCurrentRole.Contains(role));
        }
        public bool HasPermission(string permission)
        {
            return userPermissions != null && userPermissions.Contains(permission);
        }
        public bool HasAllPermissions(string[] permissions)
        {
            if (userPermissions != null)
            {
                return permissions.All(permission => userPermissions.Contains(permission));
            }
            return false;
        }
    }
}