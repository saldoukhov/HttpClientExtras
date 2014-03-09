using System;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace HttpClientExtras
{
    public static class Azure
    {
        public static IOAuthToolsPlatformAdapter PlatformAdapter { get; set; }

        public static string GetSharedKeyHeader(HttpMethod method, Uri requestUri, 
            string dateInRfc1123Format, string contentType, string accountName, string accountKey)
        {
            var canonicalizedResource = String.Format("/{0}{1}", accountName, requestUri.AbsolutePath);

            var signatureBase = String.Format(
                              "{0}\n\n{1}\n{2}\n{3}",
                              method,
                              contentType,
                              dateInRfc1123Format,
                              canonicalizedResource);
            var signature = PlatformAdapter.GetAzureSignature(signatureBase, accountKey);
            return accountName + ":" + signature;
        }
    }

    public class AzureTableMessageHandler : DelegatingHandler
    {
        private readonly string _storageAccount;
        private readonly string _accountKey;

        public AzureTableMessageHandler(string storageAccount, string accountKey)
            : base(new HttpClientHandler
                {
                    AutomaticDecompression = DecompressionMethods.GZip,
                })
        {
            _storageAccount = storageAccount;
            _accountKey = accountKey;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var dateInRfc1123Format = DateTime.UtcNow.ToString("R", CultureInfo.InvariantCulture);
            request.Headers.Add("x-ms-date", dateInRfc1123Format);

            var contentType = request.Content == null
                ? null
                : request.Content.Headers.ContentType.ToString();
            var sharedKeyHeader = Azure.GetSharedKeyHeader(request.Method, request.RequestUri, dateInRfc1123Format, contentType, _storageAccount, _accountKey);
            request.Headers.Authorization = new AuthenticationHeaderValue("SharedKey", sharedKeyHeader);

            return await base.SendAsync(request, cancellationToken);
        }
    }
}
