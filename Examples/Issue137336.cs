// https://github.com/dotnet/runtime/issues/137336
using System.Security.Cryptography;
using System.Buffers.Text;

try
{
    var PrivateKeyA = @"WRONGKmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI";
    var PublicKeyA = @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33yJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A";

    var privateKey = Base64Url.DecodeFromChars(PrivateKeyA);
    var publicKey = Base64Url.DecodeFromChars(PublicKeyA);
    var keypair = ECDsa.Create(new ECParameters
    {
        Curve = ECCurve.NamedCurves.nistP256,
        D = privateKey,
        Q = new ECPoint
        {
            X = [.. publicKey.Skip(1).Take(32)],
            Y = [.. publicKey.Skip(33)],
        }
    });
    Console.WriteLine($"Should never reach here: null={keypair is null}");
    if(keypair is not null)
    {
        var ep = keypair.ExportParameters(includePrivateParameters: true);
        if (ep.D is null) throw new InvalidOperationException();
        Console.WriteLine($"Private key: {Base64Url.EncodeToString([..ep.D])}");
    }
}
catch (CryptographicException e)
{
    Console.WriteLine($"Expected CryptographicException: {e.ToString()}");
}
catch (Exception e)
{
    Console.WriteLine($"Exception {e.Message} {e.ToString()}");
}
