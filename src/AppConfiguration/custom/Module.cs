using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.PowerShell.Cmdlets.AppConfiguration.Runtime;

using SignalDelegate = global::System.Func<string, global::System.Threading.CancellationToken, global::System.Func<global::System.EventArgs>, global::System.Threading.Tasks.Task>;
using NextDelegate = global::System.Func<global::System.Net.Http.HttpRequestMessage, global::System.Threading.CancellationToken, global::System.Action, global::System.Func<string, global::System.Threading.CancellationToken, global::System.Func<global::System.EventArgs>, global::System.Threading.Tasks.Task>, global::System.Threading.Tasks.Task<global::System.Net.Http.HttpResponseMessage>>;
using SendAsyncStepDelegate = System.Func<System.Net.Http.HttpRequestMessage, System.Threading.CancellationToken, System.Action, System.Func<string, System.Threading.CancellationToken, System.Func<System.EventArgs>, System.Threading.Tasks.Task>, System.Func<System.Net.Http.HttpRequestMessage, System.Threading.CancellationToken, System.Action, System.Func<string, System.Threading.CancellationToken, System.Func<System.EventArgs>, System.Threading.Tasks.Task>, System.Threading.Tasks.Task<System.Net.Http.HttpResponseMessage>>, System.Threading.Tasks.Task<System.Net.Http.HttpResponseMessage>>;
using System.Security.Cryptography;
using System.IO;
using System.Net.Http.Headers;

namespace Microsoft.Azure.PowerShell.Cmdlets.AppConfiguration
{
    //eriwan:auth2
    //partial class Module
    //{
    //    partial void CustomizeAuthenticationHandler(IDictionary<string, object> extensibleParameters, ref SendAsyncStepDelegate authDelegate)
    //    {
    //        if (extensibleParameters == null)
    //        {
    //            throw new ArgumentNullException(nameof(extensibleParameters));
    //        }

    //        authDelegate = new AuthenticationHandler(extensibleParameters).SendAsync;
    //        _httpPipelineBuiltInPolicy &= ~HttpPipelineBuiltInPolicy.BearToken;
    //    }
    //}

    public class AuthenticationHandler
    {
        private IDictionary<string, object> _extensibleParameters;
        public AuthenticationHandler(IDictionary<string, object> extensibleParameters)
        {
            _extensibleParameters = extensibleParameters;
        }

        public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token, Action cancel, SignalDelegate signal, NextDelegate next)
        {
            if (token.IsCancellationRequested)
            {
                cancel();
            }

            //how to get secret first?
            string id = _extensibleParameters["id"] as string;
            byte[] secret = _extensibleParameters["secret"] as byte[];
            request.Sign(id, secret);

            return next(request, token, cancel, signal);
        }
    }
    static class HttpRequestMessageExtensions
    {
        public static HttpRequestMessage Sign(this HttpRequestMessage request, string credential, byte[] secret)
        {
            string host = request.RequestUri.Authority;
            string verb = request.Method.ToString().ToUpper();
            DateTimeOffset utcNow = DateTimeOffset.UtcNow;
            string contentHash = Convert.ToBase64String(request.Content.ComputeSha256Hash());

            //
            // SignedHeaders
            string signedHeaders = "date;host;x-ms-content-sha256"; // Semicolon separated header names

            //
            // String-To-Sign
            var stringToSign = $"{verb}\n{request.RequestUri.PathAndQuery}\n{utcNow.ToString("r")};{host};{contentHash}";

            //
            // Signature
            string signature;

            using (var hmac = new HMACSHA256(secret))
            {
                signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.ASCII.GetBytes(stringToSign)));
            }

            //
            // Add headers
            request.Headers.Date = utcNow;
            request.Headers.Add("x-ms-content-sha256", contentHash);
            request.Headers.Authorization = new AuthenticationHeaderValue("HMAC-SHA256", $"Credential={credential}&SignedHeaders={signedHeaders}&Signature={signature}");

            return request;
        }
    }

    static class HttpContentExtensions
    {
        public static byte[] ComputeSha256Hash(this HttpContent content)
        {
            using (var stream = new MemoryStream())
            {
                if (content != null)
                {
                    content.CopyToAsync(stream).Wait();
                    stream.Seek(0, SeekOrigin.Begin);
                }

                using (var alg = SHA256.Create())
                {
                    return alg.ComputeHash(stream.ToArray());
                }
            }
        }
    }
}
