using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace HttpClientExtras
{
    public interface IOAuthToolsPlatformAdapter
    {
        int GetSeed();
        string GetOAuthSignature(string signatureBase, string consumerSecret, string tokenSecret);
        string GetAzureSignature(string signatureBase, string sharedKey);
    }

    public static class OAuthTools
    {
        private const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string Lower = "abcdefghijklmnopqrstuvwxyz";
        private const string Digit = "1234567890";
        private const string AlphaNumeric = Upper + Lower + Digit;
        private const string Unreserved = AlphaNumeric + "-._~";

        private static Random _random;
        private static readonly object RandomLock = new object();

        private static IOAuthToolsPlatformAdapter _platformAdapter;

        public static IOAuthToolsPlatformAdapter PlatformAdapter
        {
            get { return _platformAdapter; }
            set
            {
                _platformAdapter = value;
                _random = new Random(_platformAdapter.GetSeed());
            }
        }

        public static string GetTimestamp()
        {
            return GetTimestamp(DateTime.UtcNow);
        }

        public static string GetTimestamp(DateTime dateTime)
        {
            var timestamp = dateTime.ToUnixTime();
            return timestamp.ToString();
        }

        public static long ToUnixTime(this DateTime dateTime)
        {
            var timeSpan = (dateTime - new DateTime(1970, 1, 1));
            var timestamp = (long)timeSpan.TotalSeconds;

            return timestamp;
        }

        private static void CheckPlatformAdapter()
        {
            if (_platformAdapter == null)
                throw new Exception("PlatformAdapter is not assigned");
        }

        public static string GetNonce()
        {
            CheckPlatformAdapter();
            const string chars = (Lower + Digit);

            var nonce = new char[16];
            lock (RandomLock)
            {
                for (var i = 0; i < nonce.Length; i++)
                {
                    nonce[i] = chars[_random.Next(0, chars.Length)];
                }
            }
            return new string(nonce);
        }

        public static IEnumerable<string[]> ParseParameters(string parameters)
        {
            return parameters.Split('&').Select(x => x.Split('='));
        }

        public static Dictionary<string, string> ParseQuery(string query)
        {
            if (string.IsNullOrEmpty(query))
                return new Dictionary<string, string>();
            return ParseParameters(query.TrimStart('?'))
                .ToDictionary(x => x[0], x => x[1]);
        }

        public static string UrlEncodeStrict(string value)
        {
            var original = value;
            var ret = original
                .ToCharArray()
                .Where(c => Unreserved.IndexOf(c) < 0 && c != '%')
                .Aggregate(value, (current, c) => current.Replace(c.ToString(), c.ToString().PercentEncode()));
            return ret.Replace("%%", "%25%");
        }

        public static string PercentEncode(this string s)
        {
            var bytes = Encoding.UTF8.GetBytes(s);
            var sb = new StringBuilder();
            foreach (var b in bytes)
            {
                if ((b > 7 && b < 11) || b == 13)
                {
                    sb.Append(string.Format("%0{0:X}", b));
                }
                else
                {
                    sb.Append(string.Format("%{0:X}", b));
                }
            }
            return sb.ToString();
        }

        public static string GetSignature(string signatureBase, string consumerSecret, string tokenSecret)
        {
            CheckPlatformAdapter();
            return _platformAdapter.GetOAuthSignature(signatureBase, consumerSecret, tokenSecret);
        }
    }

    internal class OrdinalStringComparer : IComparer<string>
    {
        private static readonly IComparer<string> Instance = new OrdinalStringComparer();

        public int Compare(string x, string y)
        {
            return string.CompareOrdinal(x, y);
        }

        public static IComparer<string> Default
        {
            get { return Instance; }
        }
    }
}
