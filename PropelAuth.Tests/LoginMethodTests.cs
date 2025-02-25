using Xunit;
using PropelAuth.Models;

namespace PropelAuth.Tests
{
    public class LoginMethodTests
    {
        [Fact]
        public void Password_ShouldReturnPasswordType()
        {
            // Act
            var loginMethod = LoginMethod.Password();

            // Assert
            Assert.Equal(LoginMethodType.Password, loginMethod.Type);
            Assert.Null(loginMethod.Provider);
            Assert.Null(loginMethod.OrgId);
        }

        [Fact]
        public void MagicLink_ShouldReturnMagicLinkType()
        {
            // Act
            var loginMethod = LoginMethod.MagicLink();

            // Assert
            Assert.Equal(LoginMethodType.MagicLink, loginMethod.Type);
            Assert.Null(loginMethod.Provider);
            Assert.Null(loginMethod.OrgId);
        }

        [Fact]
        public void SocialSso_ShouldSetProviderAndType()
        {
            // Arrange
            string provider = "google";

            // Act
            var loginMethod = LoginMethod.SocialSso(provider);

            // Assert
            Assert.Equal(LoginMethodType.SocialSso, loginMethod.Type);
            Assert.Equal(provider, loginMethod.Provider);
            Assert.Null(loginMethod.OrgId);
        }

        [Fact]
        public void EmailConfirmationLink_ShouldReturnEmailConfirmationLinkType()
        {
            // Act
            var loginMethod = LoginMethod.EmailConfirmationLink();

            // Assert
            Assert.Equal(LoginMethodType.EmailConfirmationLink, loginMethod.Type);
            Assert.Null(loginMethod.Provider);
            Assert.Null(loginMethod.OrgId);
        }

        [Fact]
        public void SamlSso_ShouldSetProviderAndOrgId()
        {
            // Arrange
            string provider = "okta";
            string orgId = "org123";

            // Act
            var loginMethod = LoginMethod.SamlSso(provider, orgId);

            // Assert
            Assert.Equal(LoginMethodType.SamlSso, loginMethod.Type);
            Assert.Equal(provider, loginMethod.Provider);
            Assert.Equal(orgId, loginMethod.OrgId);
        }

        [Fact]
        public void Impersonation_ShouldReturnImpersonationType()
        {
            // Act
            var loginMethod = LoginMethod.Impersonation();

            // Assert
            Assert.Equal(LoginMethodType.Impersonation, loginMethod.Type);
            Assert.Null(loginMethod.Provider);
            Assert.Null(loginMethod.OrgId);
        }

        [Fact]
        public void GeneratedFromBackendApi_ShouldReturnCorrectType()
        {
            // Act
            var loginMethod = LoginMethod.GeneratedFromBackendApi();

            // Assert
            Assert.Equal(LoginMethodType.GeneratedFromBackendApi, loginMethod.Type);
            Assert.Null(loginMethod.Provider);
            Assert.Null(loginMethod.OrgId);
        }

        [Fact]
        public void Unknown_ShouldReturnUnknownType()
        {
            // Act
            var loginMethod = LoginMethod.Unknown();

            // Assert
            Assert.Equal(LoginMethodType.Unknown, loginMethod.Type);
            Assert.Null(loginMethod.Provider);
            Assert.Null(loginMethod.OrgId);
        }
    }
}