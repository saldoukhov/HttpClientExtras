using System;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;

namespace HttpClientExtras.RT
{
    internal class OAuthToolsPlatformAdapter : IOAuthToolsPlatformAdapter
    {
        public int GetSeed()
        {
            return (int)CryptographicBuffer.GenerateRandomNumber();
        }

        public string GetOAuthSignature(string signatureBase, string consumerSecret, string tokenSecret)
        {
            var algorithm = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");

            var keyMaterial = CryptographicBuffer
                .ConvertStringToBinary(consumerSecret + "&" + tokenSecret, BinaryStringEncoding.Utf8);

            var hmacKey = algorithm.CreateKey(keyMaterial);

            var signature = CryptographicEngine
                .Sign(hmacKey, CryptographicBuffer.ConvertStringToBinary(signatureBase, BinaryStringEncoding.Utf8));

            return Uri.EscapeDataString(CryptographicBuffer.EncodeToBase64String(signature));
        }

        public string GetAzureSignature(string signatureBase, string sharedKey)
        {
            return null;
        }
    }

    public static class PlatformAdapters
    {
        public static void Init()
        {
            OAuthTools.PlatformAdapter = new OAuthToolsPlatformAdapter();
        }
    }
}
