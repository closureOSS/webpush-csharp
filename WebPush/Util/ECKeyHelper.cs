using System.Linq;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace WebPush.Util;

internal static class ECKeyHelper
{
    public static ECDsa GetKeyPair(byte[] privateKey, byte[] publicKey)
    {
        return ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = privateKey,
            Q = new ECPoint
            {
                X = [.. publicKey.Skip(1).Take(32)],
                Y = [.. publicKey.Skip(33)],
            }
        });
    }

    public static byte[] GetPublicKey(this ECDsa keypair)
    {
        var ep = keypair.ExportParameters(true);
        return [4, .. ep.Q.X, .. ep.Q.Y];
    }


    public static byte[] GetPrivateKey(this ECDsa keypair)
    {
        var ep = keypair.ExportParameters(true);
        return [.. ep.D];
    }

    public static string GetEncodedPublicKey(this ECDsa keypair) => Base64UrlEncoder.Encode(keypair.GetPublicKey());
    public static string GetEncodedPrivateKey(this ECDsa keypair) => Base64UrlEncoder.Encode(keypair.GetPrivateKey());

    public static ECDsa GenerateKeys()
    {
        return ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }    
}