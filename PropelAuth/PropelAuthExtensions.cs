using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using PropelAuth.Models;

namespace PropelAuth
{
    /// <summary>
    /// Extension methods for configuring PropelAuth authentication in an ASP.NET Core application.
    /// </summary>
    public static class PropelAuthExtensions
    {
        /// <summary>
        /// Adds PropelAuth authentication to the service collection.
        /// </summary>
        /// <param name="services">The service collection to add authentication to.</param>
        /// <param name="options">The PropelAuth configuration options.</param>
        /// <returns>The service collection for chaining.</returns>
        /// <exception cref="Exception">Thrown when the API key is invalid or the verifier key cannot be retrieved.</exception>
        public static async Task<IServiceCollection> AddPropelAuthAsync(this IServiceCollection services,
            PropelAuthOptions options)
        {
            // Get the public key either from options or from the PropelAuth API
            string publicKey = await GetPublicKeyAsync(options);

            // Configure RSA with the public key
            var rsa = ConfigureRsaWithPublicKey(publicKey);

            // Add authentication with JWT bearer
            ConfigureAuthentication(services, options, rsa);

            return services;
        }

        #region Private Helper Methods

        /// <summary>
        /// Gets the public key either from options or from the PropelAuth API.
        /// </summary>
        /// <param name="options">The PropelAuth configuration options.</param>
        /// <returns>The public key in PEM format.</returns>
        private static async Task<string> GetPublicKeyAsync(PropelAuthOptions options)
        {
            if (!string.IsNullOrEmpty(options.PublicKey))
            {
                return options.PublicKey;
            }

            return await GetVerifierKeyPemAsync(options.AuthUrl, options.ApiKey);
        }

        /// <summary>
        /// Configures RSA with the provided public key.
        /// </summary>
        /// <param name="publicKey">The public key in PEM format.</param>
        /// <returns>An initialized RSA instance.</returns>
        private static RSA ConfigureRsaWithPublicKey(string publicKey)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(publicKey);
            return rsa;
        }

        /// <summary>
        /// Configures authentication with JWT bearer.
        /// </summary>
        /// <param name="services">The service collection to add authentication to.</param>
        /// <param name="options">The PropelAuth configuration options.</param>
        /// <param name="rsa">The RSA instance configured with the public key.</param>
        private static void ConfigureAuthentication(IServiceCollection services, PropelAuthOptions options, RSA rsa)
        {
            var authBuilder = services.AddAuthentication(authOptions =>
            {
                if (options.OAuthOptions != null)
                {
                    authOptions.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    authOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    authOptions.DefaultChallengeScheme = "PropelAuth";
                }
                else
                {
                    authOptions.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    authOptions.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                }
            });

            if (options.OAuthOptions == null)
            {
                authBuilder.AddJwtBearer(jwtOptions =>
                {
                    jwtOptions.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidAlgorithms = new List<string>() {"RS256"},
                        ValidIssuer = options.AuthUrl,
                        IssuerSigningKey = new RsaSecurityKey(rsa),
                        ValidateLifetime = true,
                    };
                });
            }
            else
            {
                authBuilder
                    .AddCookie(cookieOptions =>
                    {
                        cookieOptions.Cookie.SameSite = SameSiteMode.Lax;
                        cookieOptions.Cookie.HttpOnly = true;
                        cookieOptions.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                        cookieOptions.SlidingExpiration = true;
                    })
                    .AddOAuth("PropelAuth", configOptions =>
                    {
                        configOptions.AuthorizationEndpoint = $"{options.AuthUrl}/propelauth/oauth/authorize";
                        configOptions.TokenEndpoint = $"{options.AuthUrl}/propelauth/oauth/token";
                        configOptions.UserInformationEndpoint = $"{options.AuthUrl}/propelauth/oauth/userinfo";
                        configOptions.ClientId = options.OAuthOptions.ClientId;
                        configOptions.ClientSecret = options.OAuthOptions.ClientSecret;
                        configOptions.CallbackPath = options.OAuthOptions.CallbackPath;
                        configOptions.SaveTokens = true;
                        configOptions.Events = new OAuthEvents
                        {
                            OnCreatingTicket = context =>
                            {
                                var token = context.AccessToken;
                                var handler = new JwtSecurityTokenHandler();
                                var jwt = handler.ReadJwtToken(token);
                                foreach (var claim in jwt.Claims)
                                {
                                    context.Identity?.AddClaim(claim);
                                }
                                return Task.CompletedTask;
                            }
                        };
                    });
            }

            services.AddAuthorization();
        }

        /// <summary>
        /// Gets the verifier key in PEM format from the PropelAuth API.
        /// </summary>
        /// <param name="issuer">The PropelAuth issuer URL.</param>
        /// <param name="apiKey">The PropelAuth API key.</param>
        /// <returns>The verifier key in PEM format.</returns>
        /// <exception cref="Exception">Thrown when the API key is invalid or the verifier key cannot be retrieved.</exception>
        private static async Task<string> GetVerifierKeyPemAsync(string issuer, string apiKey)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}");
                var response = await client.GetAsync($"{issuer}/api/v1/token_verification_metadata");

                if (response.IsSuccessStatusCode)
                {
                    return await ParseVerifierKeyFromResponse(response);
                }

                throw new Exception("Error in initializing library, this is likely due to an incorrect API Key");
            }
        }

        /// <summary>
        /// Parses the verifier key from the API response.
        /// </summary>
        /// <param name="response">The HTTP response from the PropelAuth API.</param>
        /// <returns>The verifier key in PEM format.</returns>
        /// <exception cref="Exception">Thrown when the verifier key is missing in the response.</exception>
        private static async Task<string> ParseVerifierKeyFromResponse(HttpResponseMessage response)
        {
            var content = await response.Content.ReadAsStringAsync();
            var json = JObject.Parse(content);
            var verifierKeyPem = json["verifier_key_pem"]?.ToString();

            if (verifierKeyPem == null)
            {
                throw new Exception("verifier_key_pem is missing in the response");
            }

            return verifierKeyPem;
        }

        #endregion
    }
}