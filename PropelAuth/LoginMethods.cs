namespace PropelAuth.Models
{
    /// <summary>
    /// Represents the different types of login methods supported by PropelAuth.
    /// </summary>
    public enum LoginMethodType
    {
        /// <summary>
        /// Standard username/password authentication.
        /// </summary>
        Password,

        /// <summary>
        /// Authentication via a magic link sent to the user's email.
        /// </summary>
        MagicLink,

        /// <summary>
        /// Authentication via a social identity provider (e.g., Google, Facebook).
        /// </summary>
        SocialSso,

        /// <summary>
        /// Authentication via an email confirmation link.
        /// </summary>
        EmailConfirmationLink,

        /// <summary>
        /// Authentication via SAML Single Sign-On.
        /// </summary>
        SamlSso,

        /// <summary>
        /// Authentication via user impersonation.
        /// </summary>
        Impersonation,

        /// <summary>
        /// Authentication token generated from backend API.
        /// </summary>
        GeneratedFromBackendApi,

        /// <summary>
        /// Unknown authentication method.
        /// </summary>
        Unknown
    }

    /// <summary>
    /// Represents information about how a user authenticated.
    /// </summary>
    public class LoginMethod
    {
        #region Properties

        /// <summary>
        /// Gets the type of login method.
        /// </summary>
        public LoginMethodType Type { get; }

        /// <summary>
        /// Gets the identity provider for SSO authentication methods.
        /// </summary>
        /// <remarks>
        /// Only applicable for SocialSso and SamlSso login method types.
        /// </remarks>
        public string? Provider { get; }

        /// <summary>
        /// Gets the organization ID associated with the login method.
        /// </summary>
        /// <remarks>
        /// Currently only applicable for SamlSso login method type.
        /// </remarks>
        public string? OrgId { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the <see cref="LoginMethod"/> class.
        /// </summary>
        /// <param name="type">The type of login method.</param>
        /// <param name="provider">The identity provider for SSO authentication methods.</param>
        /// <param name="orgId">The organization ID associated with the login method.</param>
        private LoginMethod(LoginMethodType type, string? provider = null, string? orgId = null)
        {
            Type = type;
            Provider = provider;
            OrgId = orgId;
        }

        #endregion

        #region Factory Methods

        /// <summary>
        /// Creates a Password login method.
        /// </summary>
        /// <returns>A new instance of LoginMethod configured for password authentication.</returns>
        public static LoginMethod Password() => new LoginMethod(LoginMethodType.Password);

        /// <summary>
        /// Creates a Magic Link login method.
        /// </summary>
        /// <returns>A new instance of LoginMethod configured for magic link authentication.</returns>
        public static LoginMethod MagicLink() => new LoginMethod(LoginMethodType.MagicLink);

        /// <summary>
        /// Creates a Social SSO login method.
        /// </summary>
        /// <param name="provider">The social identity provider (e.g., "google", "facebook").</param>
        /// <returns>A new instance of LoginMethod configured for social SSO authentication.</returns>
        public static LoginMethod SocialSso(string provider) => 
            new LoginMethod(LoginMethodType.SocialSso, provider);

        /// <summary>
        /// Creates an Email Confirmation Link login method.
        /// </summary>
        /// <returns>A new instance of LoginMethod configured for email confirmation link authentication.</returns>
        public static LoginMethod EmailConfirmationLink() => 
            new LoginMethod(LoginMethodType.EmailConfirmationLink);

        /// <summary>
        /// Creates a SAML SSO login method.
        /// </summary>
        /// <param name="provider">The SAML identity provider.</param>
        /// <param name="orgId">The organization ID associated with the SAML configuration.</param>
        /// <returns>A new instance of LoginMethod configured for SAML SSO authentication.</returns>
        public static LoginMethod SamlSso(string provider, string orgId) => 
            new LoginMethod(LoginMethodType.SamlSso, provider, orgId);

        /// <summary>
        /// Creates an Impersonation login method.
        /// </summary>
        /// <returns>A new instance of LoginMethod configured for impersonation authentication.</returns>
        public static LoginMethod Impersonation() => new LoginMethod(LoginMethodType.Impersonation);

        /// <summary>
        /// Creates a Generated From Backend API login method.
        /// </summary>
        /// <returns>A new instance of LoginMethod configured for token generated from backend API.</returns>
        public static LoginMethod GeneratedFromBackendApi() => 
            new LoginMethod(LoginMethodType.GeneratedFromBackendApi);

        /// <summary>
        /// Creates an Unknown login method.
        /// </summary>
        /// <returns>A new instance of LoginMethod with an unknown authentication type.</returns>
        public static LoginMethod Unknown() => new LoginMethod(LoginMethodType.Unknown);

        #endregion
    }
}