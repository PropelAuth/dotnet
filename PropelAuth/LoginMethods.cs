namespace PropelAuth.Models
{
    public enum LoginMethodType
    {
        Password,
        MagicLink,
        SocialSso,
        EmailConfirmationLink,
        SamlSso,
        Impersonation,
        GeneratedFromBackendApi,
        Unknown
    }

    public class LoginMethod
    {
        public LoginMethodType Type { get; set; }
        public string? Provider { get; set; }
        public string? OrgId { get; set; }

        public LoginMethod(LoginMethodType type)
        {
            Type = type;
        }

        public static LoginMethod Password() => new LoginMethod(LoginMethodType.Password);
        public static LoginMethod MagicLink() => new LoginMethod(LoginMethodType.MagicLink);
        public static LoginMethod SocialSso(string provider) => new LoginMethod(LoginMethodType.SocialSso) { Provider = provider };
        public static LoginMethod EmailConfirmationLink() => new LoginMethod(LoginMethodType.EmailConfirmationLink);
        public static LoginMethod SamlSso(string provider, string orgId) => new LoginMethod(LoginMethodType.SamlSso) { Provider = provider, OrgId = orgId };
        public static LoginMethod Impersonation() => new LoginMethod(LoginMethodType.Impersonation);
        public static LoginMethod GeneratedFromBackendApi() => new LoginMethod(LoginMethodType.GeneratedFromBackendApi);
        public static LoginMethod Unknown() => new LoginMethod(LoginMethodType.Unknown);
    }
    

}