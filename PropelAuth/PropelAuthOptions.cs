namespace PropelAuth.Models
{
    /// <summary>
    /// Configuration options for PropelAuth authentication service.
    /// </summary>
    public class PropelAuthOptions
    {
        #region Properties

        /// <summary>
        /// Gets the public key used for token verification.
        /// </summary>
        /// <remarks>
        /// This key is optional, if unspecified, we will fetch the public key from the authentication service.
        /// </remarks>
        public string? PublicKey { get; }

        /// <summary>
        /// Gets the base URL for the PropelAuth authentication service.
        /// </summary>
        public string AuthUrl { get; }

        /// <summary>
        /// Gets the API key used for authenticating requests to PropelAuth.
        /// </summary>
        public string ApiKey { get; }

        /// <summary>
        /// If you are using PropelAuth's OAuth feature, you can specify the OAuth options here.
        /// </summary>
        public OAuthOptions? OAuthOptions { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="PropelAuthOptions"/> class.
        /// </summary>
        /// <param name="authUrl">The base URL for the PropelAuth authentication service.</param>
        /// <param name="apiKey">The API key used for authenticating requests to PropelAuth.</param>
        /// <param name="publicKey">Optional. The public key used for token verification.</param>
        /// <param name="oAuthOptions">Optional. The OAuth options if you are using PropelAuth's OAuth feature.</param>
        public PropelAuthOptions(string authUrl, string apiKey, string? publicKey = null,
            OAuthOptions? oAuthOptions = null)
        {
            AuthUrl = authUrl;
            ApiKey = apiKey;
            PublicKey = publicKey;
            OAuthOptions = oAuthOptions;
        }

        #endregion
    }

    public class OAuthOptions
    {
        #region Properties
        
        /// <summary>
        /// The client ID for the OAuth application.
        /// </summary>
        public string ClientId { get; }

        /// <summary>
        /// The client secret for the OAuth application.
        /// </summary>
        public string ClientSecret { get; }

        /// <summary>
        /// The callback path for the OAuth application. Defaults to "/callback"
        /// </summary>
        public string? CallbackPath { get; }
        
        /// <summary>
        /// Whether to allow requests via an authorization header `Bearer {TOKEN}`. Default false.
        /// </summary>
        public bool? AllowBearerTokenAuth { get; }
        
        #endregion

        #region Constructor
        
        /// <summary>
        /// Initializes a new instance of the <see cref="OAuthOptions"/> class.
        /// </summary>
        /// <param name="clientId">The client ID for the OAuth application.</param>
        /// <param name="clientSecret">The client secret for the OAuth application.</param>
        /// <param name="callbackPath">Optional. The callback path for the OAuth application. Defaults to "/callback"</param>
        /// <param name="allowBearerTokenAuth">Optional. Whether to allow requests via an authorization header `Bearer {TOKEN}`. Default false.</param>
        public OAuthOptions(string clientId, string clientSecret, string? callbackPath = "/callback", bool? allowBearerTokenAuth = false)
        {
            ClientId = clientId;
            ClientSecret = clientSecret;
            CallbackPath = callbackPath;
            AllowBearerTokenAuth = allowBearerTokenAuth;
        }

        #endregion
        
    }
}