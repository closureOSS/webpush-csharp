using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

[assembly: InternalsVisibleTo("WebPush.Test")]

namespace WebPush.Util;

internal static class Encryptor
{
    public static EncryptionResult Encrypt(string subscriptionPublicKeyBase64, string authSecretBase64, string payload)
    {
        var subscriptionPublicKey = Base64UrlEncoder.DecodeBytes(subscriptionPublicKeyBase64);
        var authenticationSecret = Base64UrlEncoder.DecodeBytes(authSecretBase64);

        // see https://datatracker.ietf.org/doc/html/rfc8291
        // See DOC: https://developer.chrome.com/blog/web-push-encryption#deriving_the_encryption_parameters

        using var ephemeralEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var ephemeralKeyParameters = ephemeralEcdh.ExportParameters(false);
        ArgumentNullException.ThrowIfNull(ephemeralKeyParameters.Q.X);
        ArgumentNullException.ThrowIfNull(ephemeralKeyParameters.Q.Y);
        var uncompressedEphemeralPublicKey = new byte[65];
        uncompressedEphemeralPublicKey[0] = 0x04;
        Buffer.BlockCopy(ephemeralKeyParameters.Q.X, 0, uncompressedEphemeralPublicKey, 1, 32);
        Buffer.BlockCopy(ephemeralKeyParameters.Q.Y, 0, uncompressedEphemeralPublicKey, 33, 32);
        
        using var userAgentEcdh = CreateWithPublicKey(subscriptionPublicKey);
        var sharedSecret = ephemeralEcdh.DeriveRawSecretAgreement(userAgentEcdh.PublicKey);

        Span<byte> salt = stackalloc byte[16];
        RandomNumberGenerator.Fill(salt);

        // Step 0 PRK_key
        Span<byte> prkkey = stackalloc byte[32]; // SHA256 output is 32 bytes
        HKDF.Extract(HashAlgorithmName.SHA256, sharedSecret, authenticationSecret, prkkey);

        // Step 1 IKM
        byte[] keyInfo = [.. Encoding.UTF8.GetBytes("WebPush: info"), 0x00, .. subscriptionPublicKey, .. uncompressedEphemeralPublicKey];
        Span<byte> ikm = stackalloc byte[32];
        HKDF.Expand(HashAlgorithmName.SHA256, prkkey, ikm, keyInfo);

        // Step 2 PRK
        Span<byte> prk = stackalloc byte[32];
        HKDF.Extract(HashAlgorithmName.SHA256, ikm, salt, prk);

        // Step 3 CEK
        byte[] cekInfo = [.. Encoding.UTF8.GetBytes("Content-Encoding: aes128gcm"), 0x00];
        Span<byte> cek = stackalloc byte[16];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, cek, cekInfo);

        // Step 4 NONCE
        byte[] nonceInfo = [.. Encoding.UTF8.GetBytes("Content-Encoding: nonce"), 0x00];
        Span<byte> nonce = stackalloc byte[12];
        HKDF.Expand(HashAlgorithmName.SHA256, prk, nonce, nonceInfo);

        // Step 5 Header
        var maxContentLength = BitConverter.GetBytes(Convert.ToInt32(4096));
        if (BitConverter.IsLittleEndian) { Array.Reverse(maxContentLength); }
        var asPublicLength = Convert.ToByte(uncompressedEphemeralPublicKey.Length);
        byte[] header = [.. salt, .. maxContentLength, asPublicLength, .. uncompressedEphemeralPublicKey];

        // Step 6 Payload padding
        byte[] paddedPayload = [.. Encoding.UTF8.GetBytes(payload), 0x02];

        // Step 7 Content Encryption
        var cipherText = EncryptMessage(paddedPayload, [.. cek], [.. nonce]);
        byte[] encryptedContent = [.. header, .. cipherText];

        return new EncryptionResult
        {
            Salt = [.. salt],
            Payload = encryptedContent,
            PublicKey = uncompressedEphemeralPublicKey
        };
    }

    public static ECDiffieHellman CreateWithPrivateKey(byte[] privateKey)
    {
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = privateKey,
        };
        return ECDiffieHellman.Create(parameters);
    }

    public static ECDiffieHellman CreateWithPublicKey(byte[] publicKey)
    {
        var x = new byte[32];
        var y = new byte[32];
        Buffer.BlockCopy(publicKey, 1, x, 0, 32);
        Buffer.BlockCopy(publicKey, 33, y, 0, 32);

        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = x,
                Y = y
            }
        };
        return ECDiffieHellman.Create(parameters);
    }


    /// <summary>
    /// Encrypts a byte array using AES with a given key and a new random IV.
    ///
    /// The Web Push protocol specifies a 16-byte authentication tag.
    /// </summary>
    public static byte[] EncryptMessage(byte[] payload, byte[] key, byte[] iv)
    {
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        var encryptedBytes = new byte[payload.Length];

        using (var aesGcm = new AesGcm(key, AesGcm.TagByteSizes.MaxSize))
        {
            aesGcm.Encrypt(iv, payload, encryptedBytes, tag);
        }

        // The standard requires the encrypted data and tag to be concatenated
        var output = new byte[encryptedBytes.Length + tag.Length];
        Buffer.BlockCopy(encryptedBytes, 0, output, 0, encryptedBytes.Length);
        Buffer.BlockCopy(tag, 0, output, encryptedBytes.Length, tag.Length);

        return output;
    }

    /// <summary>
    /// Decrypts a byte array using AES with a given key and IV.
    ///
    /// ciphertext must contain the tag as the end (last 16 bytes).
    /// </summary>
    public static string DecryptMessage(byte[] payload, byte[] key, byte[] nonce)
    {
        ReadOnlySpan<byte> readOnlySpan = payload;
        var tag = readOnlySpan.Slice(payload.Length - AesGcm.TagByteSizes.MaxSize, length: AesGcm.TagByteSizes.MaxSize);
        var ciphertext = readOnlySpan.Slice(0, payload.Length - AesGcm.TagByteSizes.MaxSize);
        using var aes = new AesGcm(key, tag.Length);
        var plaintextBytes = new byte[ciphertext.Length];
        aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);
        return Encoding.UTF8.GetString(plaintextBytes);
    }

    public static byte[] AddPaddingToInput(byte[] data)
    {
        var input = new byte[0 + 2 + data.Length];
        Buffer.BlockCopy(ConvertInt(0), 0, input, 0, 2);
        Buffer.BlockCopy(data, 0, input, 0 + 2, data.Length);
        return input;
    }

    public static byte[] ConvertInt(int number)
    {
        var output = BitConverter.GetBytes(Convert.ToUInt16(number));
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(output);
        }
        return output;
    }
}
