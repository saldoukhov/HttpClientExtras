using System;
using System.Security.Cryptography;
using System.Text;

namespace HttpClientExtras.WP8
{
    internal class OAuthToolsPlatformAdapter : IOAuthToolsPlatformAdapter
    {

        public int GetSeed()
        {
            var bytes = new byte[4];
            new RNGCryptoServiceProvider().GetBytes(bytes);
            return BitConverter.ToInt32(bytes, 0);
        }

        public string GetOAuthSignature(string signatureBase, string consumerSecret, string tokenSecret)
        {
            consumerSecret = Uri.EscapeDataString(consumerSecret);
            if (!string.IsNullOrEmpty(tokenSecret))
                tokenSecret = Uri.EscapeDataString(tokenSecret);
            var crypto = new HMACSHA1(Encoding.UTF8.GetBytes(consumerSecret + "&" + tokenSecret));
            var signature = HashWith(signatureBase, crypto);
            var result = Uri.EscapeDataString(signature);
            return result;
        }

        public string GetAzureSignature(string signatureBase, string sharedKey)
        {
            var crypto = new HMACSHA256(Convert.FromBase64String(sharedKey));
            var signature = HashWith(signatureBase, crypto);
            return signature;
        }
        
        private static string HashWith(string input, HashAlgorithm algorithm)
        {
            var data = Encoding.UTF8.GetBytes(input);
            var hash = algorithm.ComputeHash(data);
            return Convert.ToBase64String(hash);
        }
    }


    public static class PlatformAdapters
    {
        public static void Init()
        {
            var adapter = new OAuthToolsPlatformAdapter();
            OAuthTools.PlatformAdapter = adapter;
            Azure.PlatformAdapter = adapter;
        }
    }
}
