using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

[assembly: InternalsVisibleTo("WebPush.Test")]

namespace WebPush.Util;

internal static class Encryptor
{

    public static EncryptionResult Encrypt(string userKey, string userSecret, string payload)
    {
        var clientPublicKey = Base64UrlEncoder.DecodeBytes(userKey);
        var clientAuthSecret = Base64UrlEncoder.DecodeBytes(userSecret);

        // See DOC: https://developer.chrome.com/blog/web-push-encryption#deriving_the_encryption_parameters

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
        // DOC: You can send payloads up to a size of 4078 bytes - 4096 bytes maximum per post, 
        // DOC: with 16-bytes for encryption information and at least 2 bytes for padding.

        // DOC: Create a buffer from our data, in this case a UTF-8 encoded string
        // DOC: const plaintext = new Buffer('Push notification payload!', 'utf8');
        // DOC: const cipher = crypto.createCipheriv('id-aes128-GCM', contentEncryptionKey, nonce);
        // DOC: const result = cipher.update(Buffer.concat(padding, plaintext));
        // DOC: cipher.final();
        // DOC: Append the auth tag to the result - https://nodejs.org/api/crypto.html#crypto_cipher_getauthtag
        // DOC: return Buffer.concat([result, cipher.getAuthTag()]);
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        var paddedPayload = AddPaddingToInput(payloadBytes);

        var encryptedData = EncryptMessage(paddedPayload, [.. key], [.. nonce]);

        return new EncryptionResult
        {
            Salt = [.. salt],
            Payload = encryptedData,
            PublicKey = uncompressedEphemeralPublicKey
        };
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

    private static byte[] AddPaddingToInput(byte[] data)
    {
        var input = new byte[0 + 2 + data.Length];
        Buffer.BlockCopy(ConvertInt(0), 0, input, 0, 2);
        Buffer.BlockCopy(data, 0, input, 0 + 2, data.Length);
        return input;
    }

    private static byte[] ConvertInt(int number)
    {
        var output = BitConverter.GetBytes(Convert.ToUInt16(number));
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(output);
        }
        return output;
    }
}