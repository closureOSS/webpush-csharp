using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
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
        Assert.AreEqual(115, encrypted.Payload.Length);
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
    public void TestKeyGeneration()
    {
        var key = ECKeyHelper.GenerateKeys();

        var AuthSecret = @"BTBZMqHH6r4Tts7J_aSIgg";
        var authSecret = Base64UrlEncoder.DecodeBytes(AuthSecret);
        Span<byte> prkkey = stackalloc byte[32]; // SHA256 output is 32 bytes
        HKDF.Extract(HashAlgorithmName.SHA256, key.GetPrivateKey(), authSecret, prkkey);
        var prkKeyEncoded = Base64UrlEncoder.Encode([.. prkkey]);
    }

    [TestMethod]
    public void TestSharedKeyGeneration()
    {
        var UaPublic = @"BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
        var uaPublic = Base64UrlEncoder.DecodeBytes(UaPublic);
        var UaPrivate = @"q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
        var uaPrivate = Base64UrlEncoder.DecodeBytes(UaPrivate);

        var AsPublic = @"BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
        var asPublic = Base64UrlEncoder.DecodeBytes(AsPublic);
        var AsPrivate = @"yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
        var asPrivate = Base64UrlEncoder.DecodeBytes(AsPrivate);

        var expectedECDHSecret = @"kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs";

        //  -- For an application server:
        //   ecdh_secret = ECDH(as_private, ua_public)
        // var asKeyAS = Encryptor.CreateWithPrivateKey(asPrivate);
        // var uaKeyAS = Encryptor.CreateWithPublicKey(uaPublic);
        // var sharedSecretAS = asKeyAS.DeriveRawSecretAgreement(uaKeyAS.PublicKey);
        var sharedSecretAS = ECKeyHelper.GetECDiffieHellmanSharedKey(asPrivate, uaPublic);
        var sharedSecretDecodedAS = Base64UrlEncoder.Encode(sharedSecretAS);

        // - For a user agent:
        //   ecdh_secret = ECDH(ua_private, as_public)
        // var uaKeyUA = Encryptor.CreateWithPrivateKey(uaPrivate);
        // var asKeyUA = Encryptor.CreateWithPublicKey(asPublic);
        // var sharedSecretUA = uaKeyUA.DeriveRawSecretAgreement(asKeyUA.PublicKey);
        var sharedSecretUA = ECKeyHelper.GetECDiffieHellmanSharedKey(uaPrivate, asPublic);
        var sharedSecretDecodedUA = Base64UrlEncoder.Encode(sharedSecretUA);

        // EXPECTED ecdh_secret: kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs
        Assert.AreEqual(expectedECDHSecret, sharedSecretDecodedUA);
        Assert.AreEqual(expectedECDHSecret, sharedSecretDecodedAS);
        Assert.AreEqual(sharedSecretDecodedAS, sharedSecretDecodedUA);
    }

    [TestMethod]
    public void TestEphemeralSharedKeyGeneration()
    {
        var ephemeralEcdh = ECKeyHelper.GenerateKeys();
        var UaPublic = @"BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
        var uaPublic = Base64UrlEncoder.DecodeBytes(UaPublic);
        var UaPrivate = @"q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
        var uaPrivate = Base64UrlEncoder.DecodeBytes(UaPrivate);
        var sharedSecretAS = ECKeyHelper.GetECDiffieHellmanSharedKey(ephemeralEcdh.GetPrivateKey(), uaPublic);
        var sharedSecretDecodedAS = Base64UrlEncoder.Encode(sharedSecretAS);
        var sharedSecretUA = ECKeyHelper.GetECDiffieHellmanSharedKey(uaPrivate, ephemeralEcdh.GetPublicKey());
        var sharedSecretDecodedUA = Base64UrlEncoder.Encode(sharedSecretUA);
        Assert.AreEqual(sharedSecretDecodedAS, sharedSecretDecodedUA);
    }

    [TestMethod]
    public void Test0_HKDF_PrkKey()
    {
        // see https://datatracker.ietf.org/doc/html/rfc8291#appendix-A
        var AuthSecret = @"BTBZMqHH6r4Tts7J_aSIgg";
        var authSecret = Base64UrlEncoder.DecodeBytes(AuthSecret);

        var EcdhSecret = @"kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs";
        var ecdhSecret = Base64UrlEncoder.DecodeBytes(EcdhSecret);

        Span<byte> prkkey = stackalloc byte[32]; // SHA256 output is 32 bytes
        HKDF.Extract(HashAlgorithmName.SHA256, ecdhSecret, authSecret, prkkey);
        var prkKeyEncoded = Base64UrlEncoder.Encode([.. prkkey]);
        Assert.AreEqual(@"Snr3JMxaHVDXHWJn5wdC52WjpCtd2EIEGBykDcZW32k", prkKeyEncoded);
    }

    [TestMethod]
    public void Test1_HKDF_Ikm()
    {
        // see https://datatracker.ietf.org/doc/html/rfc8291

        //# HKDF-Expand(PRK_key, key_info, L_key=32)
        //  key_info = "WebPush: info" || 0x00 || ua_public || as_public
        //  IKM = HMAC-SHA-256(PRK_key, key_info || 0x01)

        var UaPublic = @"BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
        var uaPublic = Base64UrlEncoder.DecodeBytes(UaPublic);
        var AsPublic = @"BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
        var asPublic = Base64UrlEncoder.DecodeBytes(AsPublic);

        byte[] keyInfo = [.. Encoding.UTF8.GetBytes("WebPush: info"), 0x00, .. uaPublic, .. asPublic];
        var keyInfoDecoded = Base64UrlEncoder.Encode(keyInfo);
        Assert.AreEqual(@"V2ViUHVzaDogaW5mbwAEJXGyvs3942BVGq8e0PTNNmwRzr5VX4m8t7GGpTM5FzFo7OLr4BhZe9MEebhuPI-OztV3ylkYfpJGmQ22ggCLDgT-M_SrDepxkU21WCP3O1SUj0EwbZIHMtu5pZpTKGSCIA5Zent7wmC6HCJ5mFgJkuk5cwAvMBKiiujwa7t45ewP", keyInfoDecoded);

        var PrkKey = @"Snr3JMxaHVDXHWJn5wdC52WjpCtd2EIEGBykDcZW32k";
        // var Prk = @"09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc";
        var prkKey = Base64UrlEncoder.DecodeBytes(PrkKey);
        Span<byte> ikm = stackalloc byte[32];
        HKDF.Expand(HashAlgorithmName.SHA256, prkKey, ikm, keyInfo);
        var ikmEncoded = Base64UrlEncoder.Encode([.. ikm]);
        Assert.AreEqual(@"S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg", ikmEncoded);
        // IKM: S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg
    }

    [TestMethod]
    public void Test2_HKDF_Prk()
    {
        // see https://datatracker.ietf.org/doc/html/rfc8291#section-3.4
        // # HKDF-Extract(salt, IKM)
        //   PRK = HMAC-SHA-256(salt, IKM)
        var IKM = @"S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg";
        var ikm = Base64UrlEncoder.DecodeBytes(IKM);

        var Salt = @"DGv6ra1nlYgDCS1FRnbzlw";
        var salt = Base64UrlEncoder.DecodeBytes(Salt);

        Span<byte> prk = stackalloc byte[32];
        HKDF.Extract(HashAlgorithmName.SHA256, ikm, salt, prk);
        var prkEncoded = Base64UrlEncoder.Encode([.. prk]);
        Assert.AreEqual(@"09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc", prkEncoded);
        // PRK: 09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc
    }

    [TestMethod]
    public void Test3_HKDF_Cek()
    {
        // see https://datatracker.ietf.org/doc/html/rfc8291#section-3.4
        // # HKDF-Expand(PRK, cek_info, L_cek=16)
        //   cek_info = "Content-Encoding: aes128gcm" || 0x00
        //   CEK = HMAC-SHA-256(PRK, cek_info || 0x01)[0..15]
        var Prk = @"09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc";
        var prk = Base64UrlEncoder.DecodeBytes(Prk);
        byte[] cekInfo = [.. Encoding.UTF8.GetBytes("Content-Encoding: aes128gcm"), 0x00];
        var cekInfoDecoded = Base64UrlEncoder.Encode(cekInfo);
        Assert.AreEqual(@"Q29udGVudC1FbmNvZGluZzogYWVzMTI4Z2NtAA", cekInfoDecoded);
        // cek_info: Q29udGVudC1FbmNvZGluZzogYWVzMTI4Z2NtAA
        Span<byte> cek = stackalloc byte[16];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, cek, cekInfo);
        var keyEncoded = Base64UrlEncoder.Encode([.. cek]);
        // CEK: oIhVW04MRdy2XN9CiKLxTg
        Assert.AreEqual(@"oIhVW04MRdy2XN9CiKLxTg", keyEncoded);
    }

    [TestMethod]
    public void Test4_HKDF_Nonce()
    {
        // see https://datatracker.ietf.org/doc/html/rfc8291#section-3.4
        // # HKDF-Expand(PRK, nonce_info, L_nonce=12)
        //   nonce_info = "Content-Encoding: nonce" || 0x00
        //   NONCE = HMAC-SHA-256(PRK, nonce_info || 0x01)[0..11]
        var Prk = @"09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc";
        var prk = Base64UrlEncoder.DecodeBytes(Prk);
        byte[] nonceInfo = [.. Encoding.UTF8.GetBytes("Content-Encoding: nonce"), 0x00];
        var nonceInfoDecoded = Base64UrlEncoder.Encode(nonceInfo);
        Assert.AreEqual(@"Q29udGVudC1FbmNvZGluZzogbm9uY2UA", nonceInfoDecoded);
        // cek_info: Q29udGVudC1FbmNvZGluZzogYWVzMTI4Z2NtAA
        Span<byte> nonce = stackalloc byte[12];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, nonce, nonceInfo);
        var nonceEncoded = Base64UrlEncoder.Encode([.. nonce]);
        // NONCE: 4h_95klXJ5E_qnoN
        Assert.AreEqual(@"4h_95klXJ5E_qnoN", nonceEncoded);
    }

    [TestMethod]
    public void Test5_Header()
    {
        // https://datatracker.ietf.org/doc/html/rfc8188#section-2.1
        var Salt = @"DGv6ra1nlYgDCS1FRnbzlw";
        var salt = Base64UrlEncoder.DecodeBytes(Salt);
        // The salt, record size of 4096, and application server public key produce an 86-octet header
        // salt (16byte) 4096 application server public key (65byte)
        var AsPublic = @"BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
        var asPublic = Base64UrlEncoder.DecodeBytes(AsPublic);
        var maxContentLength = BitConverter.GetBytes(Convert.ToInt32(4096));
        if (BitConverter.IsLittleEndian) { Array.Reverse(maxContentLength); }
        var asPublicLength = Convert.ToByte(asPublic.Length);
        byte[] header = [.. salt, .. maxContentLength, asPublicLength, .. asPublic];
        var headerEncoded = Base64UrlEncoder.Encode(header);
        Assert.AreEqual(@"DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8", headerEncoded);
        // DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8
    }


    [TestMethod]
    public void Test6_ContentPadding()
    {
        var Payload = @"When I grow up, I want to be a watermelon";
        var payload = Encoding.UTF8.GetBytes(Payload);
        // var padded = Encryptor.AddPaddingToInput([.. payload]);
        var paddedPayload = Base64UrlEncoder.Encode([.. payload, 0x02]);
        Assert.AreEqual(@"V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24C", paddedPayload);
    }

    [TestMethod]
    public void Test7_ContentEncryption()
    {
        var Nonce = @"4h_95klXJ5E_qnoN";
        var nonce = Base64UrlEncoder.DecodeBytes(Nonce);
        var Cek = @"oIhVW04MRdy2XN9CiKLxTg";
        var cek = Base64UrlEncoder.DecodeBytes(Cek);
        var PaddedPayload = @"V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24C";
        var paddedPayload = Base64UrlEncoder.DecodeBytes(PaddedPayload);

        var cipherText = Encryptor.EncryptMessage(paddedPayload, cek, nonce);
        // Ciphertext: 8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ
        var cipherTextEncoded = Base64UrlEncoder.Encode(cipherText);
        Assert.AreEqual(@"8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ", cipherTextEncoded);

        var Header = @"DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
        var header = Base64UrlEncoder.DecodeBytes(Header);

        byte[] content = [.. header, .. cipherText];
        var contentEncoded = Base64UrlEncoder.Encode(content);
        Assert.AreEqual(@"DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN", contentEncoded);
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