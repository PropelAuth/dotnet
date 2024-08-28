public class PropelAuthOptions
{
    public string? PublicKey { get; set; }
    public string AuthUrl { get; set; }
    public string ApiKey { get; set; }

    public PropelAuthOptions(string authUrl, string apiKey, string? publicKey = null)
    {
        AuthUrl = authUrl;
        PublicKey = publicKey;
        ApiKey = apiKey;
    }
}