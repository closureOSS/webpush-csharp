using Microsoft.IdentityModel.Tokens;

namespace WebPush;

// @LogicSoftware
// Originally From: https://github.com/LogicSoftware/WebPushEncryption/blob/master/src/EncryptionResult.cs
public class EncryptionResult
{
    public byte[] PublicKey { get; set; }
    public byte[] Payload { get; set; }
    public byte[] Salt { get; set; }

    public string Base64EncodePublicKey()
    {
        return Base64UrlEncoder.Encode(PublicKey);
    }

    public string Base64EncodeSalt()
    {
        return Base64UrlEncoder.Encode(Salt);
    }
}