using System;
using System.Linq;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace HttpClientExtras
{
    public static class OAuth
    {

        public static Dictionary<string, string> CreateOAuthParams()
        {
            var oauthParams = new Dictionary<string, string>();
            oauthParams["oauth_nonce"] = OAuthTools.GetNonce();
            oauthParams["oauth_timestamp"] = OAuthTools.GetTimestamp();
            oauthParams["oauth_version"] = "1.0";
            return oauthParams;
        }

        public static AuthenticationHeaderValue Sign(HttpMethod method, Uri requestUri,
            Dictionary<string, string> oauthParams, Dictionary<string, string> requestParams,
            string consumerSecret, string tokenSecret)
        {
            oauthParams["oauth_signature_method"] = "HMAC-SHA1";
            oauthParams["oauth_signature"] = CreateSignature(method, requestUri,
                                                                    oauthParams, requestParams,
                                                                   consumerSecret, tokenSecret);
            return GethAuthenticationHeaderValue(oauthParams);
        }

        public static AuthenticationHeaderValue GethAuthenticationHeaderValue(Dictionary<string, string> oauthParams)
        {
            var sortedParams = oauthParams
                .OrderBy(kvp => kvp.Key)
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

            var oAuthHeader = string
                .Concat(sortedParams
                            .Where(x => !string.IsNullOrEmpty(x.Value))
                            .Select(x => x.Key + @"=""" + x.Value + @""","))
                .TrimEnd(',');

            return new AuthenticationHeaderValue("OAuth", oAuthHeader);
        }

        private static string CreateSignature(HttpMethod method, Uri requestUri,
            Dictionary<string, string> oauthParams, Dictionary<string, string> requestParams,
            string consumerSecret, string tokenSecret)
        {
            var sortedParams = requestParams
                .Concat(oauthParams)
                .OrderBy(kvp => kvp.Key, OrdinalStringComparer.Default);

            var sortedParamsStr = string.Concat(sortedParams
                                                   .Where(x => !string.IsNullOrEmpty(x.Value))
                                                   .Select(x => x.Key + "=" + x.Value + "&")).TrimEnd('&');

            var uri = requestUri.Scheme + @"://"
                   + requestUri.Host
                   + (requestUri.IsDefaultPort ? "" : ":" + requestUri.Port)
                   + requestUri.AbsolutePath;

            var signatureBase = method + "&"
                                + Uri.EscapeDataString(uri) + "&"
                                + Uri.EscapeDataString(sortedParamsStr);

            var signature = OAuthTools.GetSignature(signatureBase, consumerSecret, tokenSecret);

            return signature;
        }
    }

    public class OAuthProtectedResourceMessageHandler : DelegatingHandler
    {
        private readonly Action<Dictionary<string, string>> _customParamsAction;
        public string ConsumerKey { get; set; }
        public string ConsumerSecret { get; set; }
        public string AccessToken { get; set; }
        public string AccessTokenSecret { get; set; }

        public OAuthProtectedResourceMessageHandler(Action<Dictionary<string, string>> customParamsAction)
            : base(new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip,
            })
        {
            _customParamsAction = customParamsAction;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var oauthParams = OAuth.CreateOAuthParams();
            oauthParams["oauth_consumer_key"] = ConsumerKey;
            oauthParams["oauth_token"] = AccessToken;
            if (_customParamsAction != null)
                _customParamsAction(oauthParams);

            var requestParams = OAuthTools.ParseQuery(request.RequestUri.Query);

            var fueContent = request.Content as FormUrlEncodedContent;
            if (fueContent != null)
            {
                var paramStr = await fueContent.ReadAsStringAsync();
                foreach (var kv in OAuthTools.ParseParameters(paramStr))
                    requestParams[kv[0]] = kv[1];
            }

            request.Headers.Authorization = OAuth.Sign(request.Method, request.RequestUri,
                oauthParams, requestParams,
                ConsumerSecret, AccessTokenSecret);

            return await base.SendAsync(request, cancellationToken);
        }
    }
}
