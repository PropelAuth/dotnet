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

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="PropelAuthOptions"/> class.
        /// </summary>
        /// <param name="authUrl">The base URL for the PropelAuth authentication service.</param>
        /// <param name="apiKey">The API key used for authenticating requests to PropelAuth.</param>
        /// <param name="publicKey">Optional. The public key used for token verification.</param>
        public PropelAuthOptions(string authUrl, string apiKey, string? publicKey = null)
        {
            AuthUrl = authUrl;
            ApiKey = apiKey;
            PublicKey = publicKey;
        }

        #endregion
    }
}