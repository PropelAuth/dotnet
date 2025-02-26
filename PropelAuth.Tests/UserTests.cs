using System;
using Xunit;
using PropelAuth.Models;
using System.Security.Claims;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace PropelAuth.Tests
{
    public class UserTests
    {
        private ClaimsPrincipal CreateTestClaimsPrincipal(
            string userId = "user123",
            string email = "user@example.com",
            string? firstName = "John",
            string? lastName = "Doe",
            string? username = "johndoe",
            Dictionary<string, OrgMemberInfo>? orgs = null,
            Dictionary<string, object>? properties = null,
            string? loginMethod = null,
            string? impersonatorUserId = null,
            string? activeOrgId = null)
        {
            var claims = new List<Claim>
            {
                new Claim("user_id", userId),
                new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", email)
            };

            if (firstName != null)
            {
                claims.Add(new Claim("first_name", firstName));
            }

            if (lastName != null)
            {
                claims.Add(new Claim("last_name", lastName));
            }

            if (username != null)
            {
                claims.Add(new Claim("username", username));
            }

            if (impersonatorUserId != null)
            {
                claims.Add(new Claim("impersonator_user_id", impersonatorUserId));
            }

            if (properties != null)
            {
                claims.Add(new Claim("properties", JsonConvert.SerializeObject(properties)));
            }

            if (loginMethod != null)
            {
                claims.Add(new Claim("login_method", loginMethod));
            }

            if (activeOrgId != null && orgs != null && orgs.TryGetValue(activeOrgId, out var org))
            {
                claims.Add(new Claim("org_member_info", JsonConvert.SerializeObject(org)));
            }
            else if (orgs != null)
            {
                claims.Add(new Claim("org_id_to_org_member_info", JsonConvert.SerializeObject(orgs)));
            }


            var identity = new ClaimsIdentity(claims, "TestAuth");
            return new ClaimsPrincipal(identity);
        }

        private OrgMemberInfo CreateTestOrgMemberInfo(
            string orgId = "org123",
            string orgName = "Test Org",
            string role = "admin",
            List<string>? inheritedRolesPlusCurrentRole = null,
            List<string>? permissions = null)
        {
            return new OrgMemberInfo
            {
                orgId = orgId,
                orgName = orgName,
                urlSafeOrgName = "test-org",
                legacyOrgId = "legacy123",
                userRole = role,
                inheritedUserRolesPlusCurrentRole = inheritedRolesPlusCurrentRole ?? new List<string> {role},
                orgRoleStructure = "single_role_in_hierarchy",
                additionalRoles = new List<string>(),
                userPermissions = permissions
            };
        }

        [Fact]
        public void Constructor_ShouldInitializeBasicProperties()
        {
            // Arrange
            var principal = CreateTestClaimsPrincipal();

            // Act
            var user = new User(principal);

            // Assert
            Assert.Equal("user123", user.userId);
            Assert.Equal("user@example.com", user.email);
            Assert.Equal("John", user.firstName);
            Assert.Equal("Doe", user.lastName);
            Assert.Equal("johndoe", user.username);
            Assert.False(user.IsImpersonated());
            Assert.Equal(LoginMethodType.Unknown, user.loginMethod.Type);
        }

        [Fact]
        public void Constructor_ShouldHandleNullableProperties()
        {
            // Arrange
            var principal = CreateTestClaimsPrincipal(
                firstName: null,
                lastName: null,
                username: null
            );

            // Act
            var user = new User(principal);

            // Assert
            Assert.Equal("user123", user.userId);
            Assert.Equal("user@example.com", user.email);
            Assert.Null(user.firstName);
            Assert.Null(user.lastName);
            Assert.Null(user.username);
        }

        [Fact]
        public void Constructor_ShouldInitializeOrgs()
        {
            // Arrange
            var org = CreateTestOrgMemberInfo();
            var orgs = new Dictionary<string, OrgMemberInfo> {{"org123", org}};
            var principal = CreateTestClaimsPrincipal(orgs: orgs);

            // Act
            var user = new User(principal);

            // Assert
            Assert.NotNull(user.orgIdToOrgMemberInfo);
            Assert.Single(user.orgIdToOrgMemberInfo);
            Assert.Equal("org123", user.GetOrgs()[0].orgId);
            Assert.Equal("Test Org", user.GetOrgs()[0].orgName);
        }

        [Fact]
        public void Constructor_ShouldHandleActiveOrg()
        {
            // Arrange
            var org1 = CreateTestOrgMemberInfo(orgId: "org1", orgName: "Org One");
            var org2 = CreateTestOrgMemberInfo(orgId: "org2", orgName: "Org Two");
            var orgs = new Dictionary<string, OrgMemberInfo>
            {
                {"org1", org1},
                {"org2", org2}
            };
            var principal = CreateTestClaimsPrincipal(orgs: orgs, activeOrgId: "org2");

            // Act
            var user = new User(principal);

            // Assert
            Assert.Equal("org2", user.GetActiveOrgId());
            Assert.NotNull(user.GetActiveOrg());
            Assert.Equal("Org Two", user.GetActiveOrg()?.orgName);
        }

        [Fact]
        public void Constructor_ShouldHandleImpersonation()
        {
            // Arrange
            var principal = CreateTestClaimsPrincipal(impersonatorUserId: "admin456");

            // Act
            var user = new User(principal);

            // Assert
            Assert.Equal("admin456", user.impersonatorUserId);
            Assert.True(user.IsImpersonated());
        }

        [Fact]
        public void Constructor_ShouldParsePasswordLoginMethod()
        {
            // Arrange
            var loginMethodJson = JsonConvert.SerializeObject(new {login_method = "password"});
            var principal = CreateTestClaimsPrincipal(loginMethod: loginMethodJson);

            // Act
            var user = new User(principal);

            // Assert
            Assert.Equal(LoginMethodType.Password, user.loginMethod.Type);
        }

        [Fact]
        public void Constructor_ShouldParseMagicLinkLoginMethod()
        {
            // Arrange
            var loginMethodJson = JsonConvert.SerializeObject(new {login_method = "magic_link"});
            var principal = CreateTestClaimsPrincipal(loginMethod: loginMethodJson);

            // Act
            var user = new User(principal);

            // Assert
            Assert.Equal(LoginMethodType.MagicLink, user.loginMethod.Type);
        }

        [Fact]
        public void Constructor_ShouldParseSocialSsoLoginMethod()
        {
            // Arrange
            var loginMethodJson = JsonConvert.SerializeObject(new {login_method = "social_sso", provider = "google"});
            var principal = CreateTestClaimsPrincipal(loginMethod: loginMethodJson);

            // Act
            var user = new User(principal);

            // Assert
            Assert.Equal(LoginMethodType.SocialSso, user.loginMethod.Type);
            Assert.Equal("google", user.loginMethod.Provider);
        }

        [Fact]
        public void Constructor_ShouldParseSamlSsoLoginMethod()
        {
            // Arrange
            var loginMethodJson = JsonConvert.SerializeObject(new
                {login_method = "saml_sso", provider = "okta", org_id = "org123"});
            var principal = CreateTestClaimsPrincipal(loginMethod: loginMethodJson);

            // Act
            var user = new User(principal);

            // Assert
            Assert.Equal(LoginMethodType.SamlSso, user.loginMethod.Type);
            Assert.Equal("okta", user.loginMethod.Provider);
            Assert.Equal("org123", user.loginMethod.OrgId);
        }

        [Fact]
        public void GetOrg_ShouldReturnCorrectOrg()
        {
            // Arrange
            var org1 = CreateTestOrgMemberInfo(orgId: "org1", orgName: "Org One");
            var org2 = CreateTestOrgMemberInfo(orgId: "org2", orgName: "Org Two");
            var orgs = new Dictionary<string, OrgMemberInfo>
            {
                {"org1", org1},
                {"org2", org2}
            };
            var principal = CreateTestClaimsPrincipal(orgs: orgs);
            var user = new User(principal);

            // Act
            var result1 = user.GetOrg("org1");
            var result2 = user.GetOrg("org2");
            var resultNonExistent = user.GetOrg("org3");

            // Assert
            Assert.NotNull(result1);
            Assert.Equal("Org One", result1.orgName);

            Assert.NotNull(result2);
            Assert.Equal("Org Two", result2.orgName);

            Assert.Null(resultNonExistent);
        }

        [Fact]
        public void GetOrgs_ShouldReturnAllOrgs()
        {
            // Arrange
            var org1 = CreateTestOrgMemberInfo(orgId: "org1", orgName: "Org One");
            var org2 = CreateTestOrgMemberInfo(orgId: "org2", orgName: "Org Two");
            var orgs = new Dictionary<string, OrgMemberInfo>
            {
                {"org1", org1},
                {"org2", org2}
            };
            var principal = CreateTestClaimsPrincipal(orgs: orgs);
            var user = new User(principal);

            // Act
            var result = user.GetOrgs();

            // Assert
            Assert.Equal(2, result.Length);
            Assert.Contains(result, o => o.orgId == "org1");
            Assert.Contains(result, o => o.orgId == "org2");
        }

        [Fact]
        public void GetOrgs_ShouldReturnEmptyArray_WhenNoOrgs()
        {
            // Arrange
            var principal = CreateTestClaimsPrincipal(orgs: null);
            var user = new User(principal);

            // Act
            var result = user.GetOrgs();

            // Assert
            Assert.Empty(result);
        }

        [Fact]
        public void IsRoleInOrg_ShouldCheckRole()
        {
            // Arrange
            var org = CreateTestOrgMemberInfo(role: "admin");
            var orgs = new Dictionary<string, OrgMemberInfo> {{"org123", org}};
            var principal = CreateTestClaimsPrincipal(orgs: orgs);
            var user = new User(principal);

            // Act & Assert
            Assert.True(user.IsRoleInOrg("org123", "admin"));
            Assert.False(user.IsRoleInOrg("org123", "member"));
            Assert.False(user.IsRoleInOrg("nonexistent", "admin"));
        }

        [Fact]
        public void IsAtLeastRoleInOrg_ShouldCheckRoleHierarchy()
        {
            // Arrange
            var org = CreateTestOrgMemberInfo(
                role: "admin",
                inheritedRolesPlusCurrentRole: new List<string> {"admin", "member", "basic"}
            );
            var orgs = new Dictionary<string, OrgMemberInfo> {{"org123", org}};
            var principal = CreateTestClaimsPrincipal(orgs: orgs);
            var user = new User(principal);

            // Act & Assert
            Assert.True(user.IsAtLeastRoleInOrg("org123", "admin"));
            Assert.True(user.IsAtLeastRoleInOrg("org123", "member"));
            Assert.True(user.IsAtLeastRoleInOrg("org123", "basic"));
            Assert.False(user.IsAtLeastRoleInOrg("org123", "owner"));
            Assert.False(user.IsAtLeastRoleInOrg("nonexistent", "admin"));
        }

        [Fact]
        public void HasPermissionInOrg_ShouldCheckPermission()
        {
            // Arrange
            var org = CreateTestOrgMemberInfo(
                permissions: new List<string> {"read", "write", "delete"}
            );
            var orgs = new Dictionary<string, OrgMemberInfo> {{"org123", org}};
            var principal = CreateTestClaimsPrincipal(orgs: orgs);
            var user = new User(principal);

            // Act & Assert
            Assert.True(user.HasPermissionInOrg("org123", "read"));
            Assert.True(user.HasPermissionInOrg("org123", "write"));
            Assert.True(user.HasPermissionInOrg("org123", "delete"));
            Assert.False(user.HasPermissionInOrg("org123", "admin"));
            Assert.False(user.HasPermissionInOrg("nonexistent", "read"));
        }

        [Fact]
        public void HasAllPermissionsInOrg_ShouldCheckMultiplePermissions()
        {
            // Arrange
            var org = CreateTestOrgMemberInfo(
                permissions: new List<string> {"read", "write", "update", "delete"}
            );
            var orgs = new Dictionary<string, OrgMemberInfo> {{"org123", org}};
            var principal = CreateTestClaimsPrincipal(orgs: orgs);
            var user = new User(principal);

            // Act & Assert
            Assert.True(user.HasAllPermissionsInOrg("org123", new[] {"read", "write"}));
            Assert.True(user.HasAllPermissionsInOrg("org123", new[] {"read", "delete", "update"}));
            Assert.False(user.HasAllPermissionsInOrg("org123", new[] {"read", "admin"}));
            Assert.False(user.HasAllPermissionsInOrg("nonexistent", new[] {"read"}));
        }

        [Fact]
        public void GetUserProperty_ShouldReturnPropertyValue()
        {
            // Arrange
            var properties = new Dictionary<string, object>
            {
                {"isPremium", true},
                {"lastLogin", "2023-08-15"},
                {"loginCount", 42}
            };
            var principal = CreateTestClaimsPrincipal(properties: properties);
            var user = new User(principal);

            // Act & Assert
            Assert.Equal(true, user.GetUserProperty("isPremium"));
            Assert.Equal("2023-08-15", user.GetUserProperty("lastLogin"));
            Assert.Equal(42, Convert.ToInt32(user.GetUserProperty("loginCount")));
            Assert.Null(user.GetUserProperty("nonexistent"));
        }

        [Fact]
        public void GetUserProperty_ShouldReturnNull_WhenPropertiesNull()
        {
            // Arrange
            var principal = CreateTestClaimsPrincipal(properties: null);
            var user = new User(principal);

            // Act & Assert
            Assert.Null(user.GetUserProperty("anyProperty"));
        }
    }
}