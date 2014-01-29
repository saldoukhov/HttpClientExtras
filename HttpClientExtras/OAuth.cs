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
        public static Dictionary<string, string> CreateOAuthParams(string consumerKey)
        {
            var oauthParams = new Dictionary<string, string>();
            oauthParams["oauth_consumer_key"] = consumerKey;
            oauthParams["oauth_nonce"] = OAuthTools.GetNonce();
            oauthParams["oauth_timestamp"] = OAuthTools.GetTimestamp();
            oauthParams["oauth_signature_method"] = "HMAC-SHA1";
            oauthParams["oauth_version"] = "1.0";
            return oauthParams;
        }

        public static string CreateSignature(HttpMethod method, Uri requestUri, 
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

        public static string GetOAuthHeader(Dictionary<string, string> headerParams)
        {
            var sortedParams = headerParams
                .OrderBy(kvp => kvp.Key)
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

            var header = string
                .Concat(sortedParams
                            .Where(x => !string.IsNullOrEmpty(x.Value))
                            .Select(x => x.Key + @"=""" + x.Value + @""","))
                .TrimEnd(',');

            return header;
        }
    }

    public class OAuthClientAuthMessageHandler : DelegatingHandler
    {
        private readonly string _consumerKey;
        private readonly string _consumerSecret;
        private readonly string _userName;
        private readonly string _password;

        public OAuthClientAuthMessageHandler(
            string consumerKey,
            string consumerSecret,
            string userName,
            string password)
            : base(new HttpClientHandler())
        {
            _consumerKey = consumerKey;
            _consumerSecret = consumerSecret;
            _userName = userName;
            _password = password;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var oauthParams = OAuth.CreateOAuthParams(_consumerKey);
            oauthParams["xoauth_login_name"] = OAuthTools.UrlEncodeStrict(_userName);
            oauthParams["xoauth_password"] = OAuthTools.UrlEncodeStrict(_password);
            oauthParams["xoauth_mode"] = "client_auth";
            oauthParams["oauth_signature"] = OAuth.CreateSignature(HttpMethod.Get, request.RequestUri, 
                                                                    oauthParams, new Dictionary<string, string>(), 
                                                                   _consumerSecret, null);
            var oAuthHeader = OAuth.GetOAuthHeader(oauthParams);
            request.Headers.Authorization = new AuthenticationHeaderValue("OAuth", oAuthHeader);
            return base.SendAsync(request, cancellationToken);
        }
    }

    public class OAuthProtectedResourceMessageHandler : DelegatingHandler
    {
        public string ConsumerKey { get; set; }
        public string ConsumerSecret { get; set; }
        public string AccessToken { get; set; }
        public string AccessTokenSecret { get; set; }

        public OAuthProtectedResourceMessageHandler()
            : base(new HttpClientHandler
                {
                    AutomaticDecompression = DecompressionMethods.GZip,
                })
        {
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var oauthParams = OAuth.CreateOAuthParams(ConsumerKey);
            oauthParams["oauth_token"] = AccessToken;
            var headerParams = new Dictionary<string, string>(oauthParams);

            var requestParams = OAuthTools.ParseQuery(request.RequestUri.Query);

            var fueContent = request.Content as FormUrlEncodedContent;
            if (fueContent != null)
            {
                var paramStr = await fueContent.ReadAsStringAsync();
                foreach (var kv in OAuthTools.ParseParameters(paramStr))
                    requestParams[kv[0]] = kv[1];
            }

            headerParams["oauth_signature"] = OAuth.CreateSignature(request.Method, request.RequestUri, 
                                                                    oauthParams, requestParams,
                                                                    ConsumerSecret, AccessTokenSecret);
            var oAuthHeader = OAuth.GetOAuthHeader(headerParams);
            request.Headers.Authorization = new AuthenticationHeaderValue("OAuth", oAuthHeader);
            return await base.SendAsync(request, cancellationToken);
        }
    }
}
