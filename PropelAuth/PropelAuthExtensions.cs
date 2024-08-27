using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace PropelAuth
{
    public static class PropelAuthExtensions
    {
        public static async Task<IServiceCollection> AddPropelAuthAsync(this IServiceCollection services, PropelAuthOptions options)
        {
            string publicKey = options.PublicKey;

            if (!string.IsNullOrEmpty(options.ApiKey))
            {
                publicKey = await GetVerifierKeyPemAsync(options.AuthUrl, options.ApiKey);
            }

            if (string.IsNullOrEmpty(publicKey))
            {
                throw new Exception("Error in initializing library, this is likely due to an incorrect API Key");
            }

            var rsa = RSA.Create();
            rsa.ImportFromPem(publicKey);

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(jwtOptions =>
                {
                    jwtOptions.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidAlgorithms = new List<string>() { "RS256" },
                        ValidIssuer = options.AuthUrl,
                        IssuerSigningKey = new RsaSecurityKey(rsa)
                    };
                });

            services.AddAuthorization();

            return services;
        }

        private static async Task<string> GetVerifierKeyPemAsync(string issuer, string apiKey)
        {
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}");
                var response = await client.GetAsync($"{issuer}/api/v1/token_verification_metadata");

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var json = JObject.Parse(content);
                    return json["verifier_key_pem"].ToString();
                }
                else
                {
                    throw new Exception("Error in initializing library, this is likely due to an incorrect API Key");
                }
            }
        }
    }
}