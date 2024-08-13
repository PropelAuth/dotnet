using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace PropelAuth
{
    public static class PropelAuthExtensions
    {
        public static IServiceCollection AddPropelAuth(this IServiceCollection services, PropelAuthOptions options)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(options.PublicKey);

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(jwtOptions =>
                {
                    jwtOptions.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                        ValidAlgorithms = new List<string>() { "RS256" },
                        ValidIssuer = options.Issuer,
                        IssuerSigningKey = new RsaSecurityKey(rsa)
                    };
                });

            services.AddAuthorization();

            return services;
        }
    }
}