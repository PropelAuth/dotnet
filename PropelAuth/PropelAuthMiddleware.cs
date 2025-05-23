using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;

namespace PropelAuth.Middleware
{
    /// <summary>
    /// Middleware that automatically refreshes tokens on each request if they're close to expiration.
    /// </summary>
    public class TokenRefreshMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<TokenRefreshMiddleware> _logger;
        private readonly string _authUrl;
        private readonly string _clientId;
        private readonly string _clientSecret;

        public TokenRefreshMiddleware(
            RequestDelegate next, 
            ILogger<TokenRefreshMiddleware> logger,
            string authUrl,
            string clientId,
            string clientSecret)
        {
            _next = next;
            _logger = logger;
            _authUrl = authUrl;
            _clientId = clientId;
            _clientSecret = clientSecret;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context.User.Identity?.IsAuthenticated == true)
            {
                await RefreshTokenIfNeeded(context);
            }

            await _next(context);
        }

        private async Task RefreshTokenIfNeeded(HttpContext context)
        {
            try
            {
                var authResult = await context.AuthenticateAsync();
                
                if (authResult.Succeeded && authResult.Properties != null)
                {
                    var accessToken = authResult.Properties.GetTokenValue("access_token");
                    var refreshToken = authResult.Properties.GetTokenValue("refresh_token");

                    if (ShouldRefreshToken(accessToken) && !string.IsNullOrEmpty(refreshToken))
                    {
                        var newTokens = await RefreshAccessTokenAsync(refreshToken);
                        if (newTokens != null)
                        {
                            await UpdateUserTokens(context, authResult, newTokens);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred during token refresh: {Message}", ex.Message);
            }
        }

        private bool ShouldRefreshToken(string? accessToken)
        {
            if (string.IsNullOrEmpty(accessToken))
                return true;

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwt = handler.ReadJwtToken(accessToken);
                
                // Refresh if token expires within the next 10 minutes
                return jwt.ValidTo <= DateTime.UtcNow.AddMinutes(20);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not parse JWT token: {Message}", ex.Message);
                return true;
            }
        }

        private async Task<TokenRefreshResult?> RefreshAccessTokenAsync(string refreshToken)
        {
            using var client = new HttpClient();
            
            var tokenRequest = new Dictionary<string, string>
            {
                {"grant_type", "refresh_token"},
                {"refresh_token", refreshToken},
                {"client_id", _clientId},
                {"client_secret", _clientSecret}
            };

            var requestContent = new FormUrlEncodedContent(tokenRequest);
            
            try
            {
                var response = await client.PostAsync($"{_authUrl}/propelauth/oauth/token", requestContent);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var json = JObject.Parse(content);
                    
                    return new TokenRefreshResult
                    {
                        AccessToken = json["access_token"]?.ToString(),
                        RefreshToken = json["refresh_token"]?.ToString(),
                        ExpiresIn = json["expires_in"]?.ToObject<int>() ?? 3600
                    };
                }
                else
                {
                    _logger.LogWarning("Token refresh failed with status: {StatusCode}", response.StatusCode);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception occurred while refreshing token: {Message}", ex.Message);
            }

            return null;
        }

        private async Task UpdateUserTokens(HttpContext context, AuthenticateResult authResult, TokenRefreshResult tokens)
        {
            if (authResult.Properties != null && !string.IsNullOrEmpty(tokens.AccessToken))
            {
                authResult.Properties.UpdateTokenValue("access_token", tokens.AccessToken);
                
                if (!string.IsNullOrEmpty(tokens.RefreshToken))
                {
                    authResult.Properties.UpdateTokenValue("refresh_token", tokens.RefreshToken);
                }

                authResult.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(tokens.ExpiresIn);

                var updatedPrincipal = UpdateClaimsFromNewToken(authResult.Principal, tokens.AccessToken);
                
                await context.SignInAsync(updatedPrincipal, authResult.Properties);
            }
        }

        private System.Security.Claims.ClaimsPrincipal UpdateClaimsFromNewToken(System.Security.Claims.ClaimsPrincipal currentPrincipal, string newAccessToken)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwt = handler.ReadJwtToken(newAccessToken);

                var newIdentity = new System.Security.Claims.ClaimsIdentity(currentPrincipal.Identity?.AuthenticationType);

                foreach (var claim in jwt.Claims)
                {
                    newIdentity.AddClaim(new System.Security.Claims.Claim(claim.Type, claim.Value));
                }

                var jwtClaimTypes = jwt.Claims.Select(c => c.Type).ToHashSet();
                foreach (var existingClaim in currentPrincipal.Claims)
                {
                    if (!jwtClaimTypes.Contains(existingClaim.Type))
                    {
                        newIdentity.AddClaim(existingClaim);
                    }
                }

                return new System.Security.Claims.ClaimsPrincipal(newIdentity);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to update claims from new token, keeping existing claims");
                return currentPrincipal;
            }
        }
    }

    public class TokenRefreshResult
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public int ExpiresIn { get; set; }
    }

    /// <summary>
    /// Extension methods for adding the token refresh middleware.
    /// </summary>
    public static class TokenRefreshMiddlewareExtensions
    {
        public static IApplicationBuilder UseTokenRefresh(
            this IApplicationBuilder builder, 
            string authUrl, 
            string clientId, 
            string clientSecret)
        {
            return builder.UseMiddleware<TokenRefreshMiddleware>(authUrl, clientId, clientSecret);
        }
    }
}