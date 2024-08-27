public class PropelAuthOptions
{
    public string? PublicKey { get; set; }
    public string AuthUrl { get; set; }
    public string? ApiKey { get; set; }

    public PropelAuthOptions(string authUrl, string? publicKey = null, string? apiKey = null)
    {
        AuthUrl = authUrl;
        PublicKey = publicKey;
        ApiKey = apiKey;

        if (string.IsNullOrEmpty(publicKey) && string.IsNullOrEmpty(apiKey))
        {
            throw new ArgumentException("Either PublicKey or ApiKey must be provided.");
        }
    }
}