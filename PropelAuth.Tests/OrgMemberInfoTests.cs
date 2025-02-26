using System;
using Xunit;
using PropelAuth.Models;
using System.Collections.Generic;
using System.Linq;

namespace PropelAuth.Tests
{
    public class OrgMemberInfoTests
    {
        private OrgMemberInfo CreateTestOrgMemberInfo(
            string role = "admin",
            List<string>? inheritedRolesPlusCurrentRole = null,
            List<string>? permissions = null)
        {
            return new OrgMemberInfo
            {
                orgId = "org123",
                orgName = "Test Organization",
                urlSafeOrgName = "test-organization",
                legacyOrgId = "legacy123",
                orgMetadata = new Dictionary<string, object> {{"industry", "technology"}},
                userRole = role,
                inheritedUserRolesPlusCurrentRole = inheritedRolesPlusCurrentRole ?? new List<string> {role},
                orgRoleStructure = "single_role_in_hierarchy",
                additionalRoles = null,
                userPermissions = permissions
            };
        }

        private OrgMemberInfo CreateTestOrgMemberInfoMultiRole(List<string> roles) {
            return new OrgMemberInfo
            {
                orgId = "org123",
                orgName = "Test Organization",
                urlSafeOrgName = "test-organization",
                legacyOrgId = "legacy123",
                orgMetadata = new Dictionary<string, object> {{"industry", "technology"}},
                userRole = roles.First(),
                inheritedUserRolesPlusCurrentRole = roles,
                orgRoleStructure = "multi_role",
                additionalRoles = roles.Skip(1).ToList(),
                userPermissions = null,
            };
        }

        [Fact]
        public void IsRole_ShouldReturnTrue_WhenRoleMatches()
        {
            // Arrange
            var orgMemberInfo = CreateTestOrgMemberInfo(role: "admin");

            // Act & Assert
            Assert.True(orgMemberInfo.IsRole("admin"));
            Assert.False(orgMemberInfo.IsRole("member"));
            Assert.False(orgMemberInfo.IsRole("owner"));
        }

        [Fact]
        public void IsAtLeastRole_ShouldReturnTrue_WhenRoleMatchesOrInherited()
        {
            // Arrange
            var orgMemberInfo = CreateTestOrgMemberInfo(
                role: "admin",
                inheritedRolesPlusCurrentRole: new List<string> {"admin", "member", "basic"}
            );

            // Act & Assert
            Assert.True(orgMemberInfo.IsAtLeastRole("admin"));
            Assert.True(orgMemberInfo.IsAtLeastRole("member"));
            Assert.True(orgMemberInfo.IsAtLeastRole("basic"));
            Assert.False(orgMemberInfo.IsAtLeastRole("owner"));
        }

        [Fact]
        public void HasPermission_ShouldReturnTrue_WhenPermissionExists()
        {
            // Arrange
            var orgMemberInfo = CreateTestOrgMemberInfo(
                permissions: new List<string> {"read", "write", "delete"}
            );

            // Act & Assert
            Assert.True(orgMemberInfo.HasPermission("read"));
            Assert.True(orgMemberInfo.HasPermission("write"));
            Assert.True(orgMemberInfo.HasPermission("delete"));
            Assert.False(orgMemberInfo.HasPermission("admin"));
        }

        [Fact]
        public void HasPermission_ShouldReturnFalse_WhenPermissionsNull()
        {
            // Arrange
            var orgMemberInfo = CreateTestOrgMemberInfo(permissions: null);

            // Act & Assert
            Assert.False(orgMemberInfo.HasPermission("read"));
        }

        [Fact]
        public void HasAllPermissions_ShouldReturnTrue_WhenAllPermissionsExist()
        {
            // Arrange
            var orgMemberInfo = CreateTestOrgMemberInfo(
                permissions: new List<string> {"read", "write", "delete", "manage"}
            );

            // Act & Assert
            Assert.True(orgMemberInfo.HasAllPermissions(new[] {"read", "write"}));
            Assert.True(orgMemberInfo.HasAllPermissions(new[] {"read", "delete", "manage"}));
            Assert.False(orgMemberInfo.HasAllPermissions(new[] {"read", "admin"}));
        }

        [Fact]
        public void HasAllPermissions_ShouldReturnFalse_WhenPermissionsNull()
        {
            // Arrange
            var orgMemberInfo = CreateTestOrgMemberInfo(permissions: null);

            // Act & Assert
            Assert.False(orgMemberInfo.HasAllPermissions(new[] {"read"}));
        }

        [Fact]
        public void HasAllPermissions_ShouldReturnTrue_WhenEmptyPermissionsRequested()
        {
            // Arrange
            var orgMemberInfo = CreateTestOrgMemberInfo(
                permissions: new List<string> {"read", "write"}
            );

            // Act & Assert
            Assert.True(orgMemberInfo.HasAllPermissions(Array.Empty<string>()));
        }
        
        [Fact]
        public void IsRole_ShouldReturnTrue_WhenRoleMatchesMultiRole()
        {
            // Arrange
            var orgMemberInfo = CreateTestOrgMemberInfoMultiRole(new List<string> {"admin", "member"});

            // Act & Assert
            Assert.True(orgMemberInfo.IsRole("admin"));
            Assert.False(orgMemberInfo.IsRole("owner"));
        }
    }
}