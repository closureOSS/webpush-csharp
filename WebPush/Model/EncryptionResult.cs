using System.Buffers.Text;

namespace WebPush.Model;

public sealed class EncryptionResult
{
    public required byte[] PublicKey { get; set; }
    public required byte[] Payload { get; set; }
    public required byte[] Salt { get; set; }

    public string Base64EncodePublicKey()
    {
        return Base64Url.EncodeToString(PublicKey);
    }

    public string Base64EncodeSalt()
    {
        return Base64Url.EncodeToString(Salt);
    }
}
