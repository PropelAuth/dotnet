public class PropelAuthOptions
{
    public string PublicKey { get; set; }
    public string Issuer { get; set; }

    public PropelAuthOptions(string publicKey, string issuer)
    {
        PublicKey = publicKey;
        Issuer = issuer;
    }
}