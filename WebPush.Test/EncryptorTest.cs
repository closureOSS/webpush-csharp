using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using WebPush.Util;

namespace WebPush.Test;

[TestClass]
public class EncryptorTest
{
    private const string TestPublicKey =
        @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33yJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A";

    private const string TestPrivateKey = @"on6X5KmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI";

    private const string TestFirefoxEndpoint =
        @"https://updates.push.services.mozilla.com/wpush/v2/gBABAABgOe_sGrdrsT35ljtA4O9xCX";

    public const string TestPayload = @"test payload";

    [TestMethod]
    public void TestEncryptionBasic()
    {
        var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);
        var encrypted = Encryptor.Encrypt(subscription.P256DH, subscription.Auth, TestPayload);

        Assert.AreEqual(16, encrypted.Salt.Length);
        Assert.AreEqual(65, encrypted.PublicKey.Length);
        Assert.AreEqual(30, encrypted.Payload.Length);
    }

  
    [TestMethod]
    public void TestGenericDH()
    {
        Span<byte> nonce = stackalloc byte[AesGcm.NonceByteSizes.MaxSize];
        RandomNumberGenerator.Fill(nonce);
        using var alice = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var bob = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        ECDiffieHellmanPublicKey alicePublicKey = alice.PublicKey;
        ECDiffieHellmanPublicKey bobPublicKey = bob.PublicKey;
        byte[] aliceSharedSecret = alice.DeriveKeyFromHash(bobPublicKey, HashAlgorithmName.SHA256);
        byte[] bobSharedSecret = bob.DeriveKeyFromHash(alicePublicKey, HashAlgorithmName.SHA256);

        Assert.IsTrue(aliceSharedSecret.SequenceEqual(bobSharedSecret));

        byte[] encryptedMessage = Encryptor.EncryptMessage(Encoding.UTF8.GetBytes(TestPayload), aliceSharedSecret, [.. nonce]);
        string decryptedMessage = Encryptor.DecryptMessage(encryptedMessage, bobSharedSecret, [.. nonce]);
        Assert.AreEqual(TestPayload, decryptedMessage);
    }

    [TestMethod]
    public void WORK()
    {
        var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);
        var clientPublicKey = Base64UrlEncoder.DecodeBytes(subscription.P256DH);
        var clientAuthSecret = Base64UrlEncoder.DecodeBytes(subscription.Auth);
        var payloadBytes = Encoding.UTF8.GetBytes(TestPayload);

        // DOC is https://developer.chrome.com/blog/web-push-encryption#deriving_the_encryption_parameters

        // see https://github.com/andreimilto/HKDF.Standard
        using var ephemeralEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var ephemeralKeyParameters = ephemeralEcdh.ExportParameters(false);
        var uncompressedEphemeralPublicKey = new byte[65];
        uncompressedEphemeralPublicKey[0] = 0x04;
        Buffer.BlockCopy(ephemeralKeyParameters.Q.X, 0, uncompressedEphemeralPublicKey, 1, 32);
        Buffer.BlockCopy(ephemeralKeyParameters.Q.Y, 0, uncompressedEphemeralPublicKey, 33, 32);

        var userAgentKeyParameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = new byte[32],
                Y = new byte[32]
            }
        };
        Array.Copy(clientPublicKey, 1, userAgentKeyParameters.Q.X, 0, 32);
        Array.Copy(clientPublicKey, 33, userAgentKeyParameters.Q.Y, 0, 32);
        using var userAgentEcdh = ECDiffieHellman.Create(userAgentKeyParameters);
        // DOC: const serverECDH = crypto.createECDH('prime256v1');
        // DOC: const serverPublicKey = serverECDH.generateKeys();
        // DOC: const sharedSecret = serverECDH.computeSecret(clientPublicKey); // Input Keying Material
        var sharedSecret = ephemeralEcdh.DeriveKeyMaterial(userAgentEcdh.PublicKey);

        Span<byte> salt = stackalloc byte[16];
        RandomNumberGenerator.Fill(salt);

        // byte[] pseudoRandomKey = ephemeralEcdh.DeriveKeyFromHmac(userAgentEcdh.PublicKey, HashAlgorithmName.SHA256, [.. salt]);

        // DOC: const authInfo = new Buffer('Content-Encoding: auth\0', 'utf8');
        var authInfo = Encoding.UTF8.GetBytes("Content-Encoding: auth\0");
        // DOC: const prk = hkdf(clientAuthSecret, sharedSecret, authInfo, 32);
        Span<byte> prk = stackalloc byte[32]; // SHA256 output is 32 bytes
        HKDF.Extract(HashAlgorithmName.SHA256, sharedSecret, salt, prk);

        // byte[] outputKeyMaterial = HKDF.Expand(HashAlgorithmName.SHA256, pseudoRandomKey, 32, Encoding.UTF8.GetBytes("Content-Encoding: auth\0"));


        // DOC: Derive the Content Encryption Key
        // DOC: const contentEncryptionKeyInfo = createInfo('aesgcm', clientPublicKey, serverPublicKey);
        // DOC: const contentEncryptionKey = hkdf(salt, prk, contentEncryptionKeyInfo, 16);
        Span<byte> key = stackalloc byte[16];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, key, Encoding.UTF8.GetBytes("aesgcm"));

        // DOC: Derive the Nonce
        // DOC: const nonceInfo = createInfo('nonce', clientPublicKey, serverPublicKey);
        // DOC: const nonce = hkdf(salt, prk, nonceInfo, 12);
        Span<byte> nonce = stackalloc byte[12];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, nonce, Encoding.UTF8.GetBytes("nonce"));


        // DOC: Now we finally have all of the things to do the encryption. 
        // DOC: The cipher required for Web Push is AES128 using GCM. 
        // DOC: We use our content encryption key as the key and the nonce as the initialization vector (IV).
        // DOC: In this example our data is a string, but it could be any binary data. 
        // DOC: You can send payloads up to a size of 4078 bytes - 4096 bytes maximum per post, 
        // DOC: with 16-bytes for encryption information and at least 2 bytes for padding.

        // DOC: Create a buffer from our data, in this case a UTF-8 encoded string
        // DOC: const plaintext = new Buffer('Push notification payload!', 'utf8');
        // DOC: const cipher = crypto.createCipheriv('id-aes128-GCM', contentEncryptionKey, nonce);
        // DOC: const result = cipher.update(Buffer.concat(padding, plaintext));
        // DOC: cipher.final();
        // DOC: Append the auth tag to the result - https://nodejs.org/api/crypto.html#crypto_cipher_getauthtag
        // DOC: return Buffer.concat([result, cipher.getAuthTag()]);
        var encryptedData = Encryptor.EncryptMessage(payloadBytes, [.. key], [.. nonce]);
        //  return (encryptedData, uncompressedEphemeralPublicKey, salt.ToArray());
        // var prk = HKDF.Expand(HashAlgorithmName.SHA256, pseudoRandomKey, 32, Encoding.UTF8.GetBytes("Content-Encoding: auth\0"));

        // DOC: Three headers
        // DOC: Encryption: salt=<SALT>
        // DOC: Crypto-Key: dh=<PUBLICKEY>
        // DOC: Content-Encoding: aesgcm

        // Verify with https://tests.peter.sh/push-encryption-verifier/

        // var prk0 = HKDF.DeriveKey(HashAlgorithmName.SHA256, userSecretBytes, 32, [.. salt], Encoding.UTF8.GetBytes("Content-Encoding: auth\0"));
        // var prk = HKDF.Expand(HashAlgorithmName.SHA256, userSecretBytes, 32, Encoding.UTF8.GetBytes("Content-Encoding: auth\0"));
        // var cek = HKDF.Expand(salt, prk, 16, Encryptor.CreateInfoChunk("aesgcm", userKeyBytes, serverPublicKey));

        // var serverPublicKey = Base64UrlEncoder.DecodeBytes(TestPublicKey);
        // using var nobody = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        // byte[] secretKey = [.. nobody.ExportParameters(true).D];


        // var serverPublicKeyParameters = new ECParameters
        // {
        //     Curve = ECCurve.NamedCurves.nistP256,
        //     D = secretKey,
        //     Q = new ECPoint
        //     {
        //         X = [.. serverPublicKey.Skip(1).Take(32)],
        //         Y = [.. serverPublicKey.Skip(33)],
        //     }
        // };


        // using ECDiffieHellmanPublicKey alicePublicKey = alice.PublicKey;
        // using ECDiffieHellmanPublicKey bobPublicKey = bob.PublicKey;
        // byte[] aliceSharedSecret = alice.DeriveKeyFromHash(bobPublicKey, HashAlgorithmName.SHA256);
        // byte[] bobSharedSecret = bob.DeriveKeyFromHash(alicePublicKey, HashAlgorithmName.SHA256);

        // Assert.IsTrue(aliceSharedSecret.SequenceEqual(bobSharedSecret));

        // byte[] encryptedMessage = Encryptor.EncryptMessage(Encoding.UTF8.GetBytes(TestPayload), aliceSharedSecret, [.. salt]);
        // string decryptedMessage = Encryptor.DecryptMessage(encryptedMessage, bobSharedSecret, [.. salt]);
        // Assert.AreEqual(TestPayload, decryptedMessage);
    }
}