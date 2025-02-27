using PropelAuth.Models;
using Xunit;

namespace PropelAuth.Tests
{
    public class PropelAuthOptionsTests
    {
        [Fact]
        public void Constructor_ShouldInitializeProperties()
        {
            // Arrange
            string authUrl = "https://auth.example.com";
            string apiKey = "api_12345";
            string publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...";

            // Act
            var options = new PropelAuthOptions(authUrl, apiKey, publicKey);

            // Assert
            Assert.Equal(authUrl, options.AuthUrl);
            Assert.Equal(apiKey, options.ApiKey);
            Assert.Equal(publicKey, options.PublicKey);
        }

        [Fact]
        public void Constructor_ShouldAcceptNullPublicKey()
        {
            // Arrange
            string authUrl = "https://auth.example.com";
            string apiKey = "api_12345";

            // Act
            var options = new PropelAuthOptions(authUrl, apiKey);

            // Assert
            Assert.Equal(authUrl, options.AuthUrl);
            Assert.Equal(apiKey, options.ApiKey);
            Assert.Null(options.PublicKey);
        }
    }
}