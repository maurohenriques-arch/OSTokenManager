using System.Net;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TokenManager.Structures;

namespace TokenManager.Tests
{
    /// <summary>
    /// End-to-end tests of GetTokensFromUrl against a local HTTP token endpoint.
    /// No internet access is needed. The TLS path is covered by ValidateServerCertificate tests.
    /// </summary>
    [TestClass()]
    public class LocalTokenEndpointTests
    {
        private sealed class CapturedRequest
        {
            public string Body = string.Empty;
        }

        private static int GetFreePort()
        {
            var probe = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            probe.Start();
            int port = ((IPEndPoint)probe.LocalEndpoint).Port;
            probe.Stop();
            return port;
        }

        private static HttpListener StartListener(int port)
        {
            var listener = new HttpListener();
            listener.Prefixes.Add($"http://localhost:{port}/");
            listener.Start();
            return listener;
        }

        // Answers exactly one request and records its form body.
        private static Task<CapturedRequest> StartOneShotServer(HttpListener listener, int statusCode, string responseBody)
        {
            return Task.Run(async () =>
            {
                HttpListenerContext context = await listener.GetContextAsync();
                var captured = new CapturedRequest();
                using (var reader = new StreamReader(context.Request.InputStream, Encoding.UTF8))
                {
                    captured.Body = await reader.ReadToEndAsync();
                }

                byte[] bytes = Encoding.UTF8.GetBytes(responseBody);
                context.Response.StatusCode = statusCode;
                context.Response.ContentType = "application/json";
                context.Response.ContentLength64 = bytes.Length;
                await context.Response.OutputStream.WriteAsync(bytes);
                context.Response.Close();
                return captured;
            });
        }

        private static void WithSecureGateway(string? value, Action action)
        {
            string? original = Environment.GetEnvironmentVariable("SECURE_GATEWAY");
            try
            {
                Environment.SetEnvironmentVariable("SECURE_GATEWAY", value);
                action();
            }
            finally
            {
                Environment.SetEnvironmentVariable("SECURE_GATEWAY", original);
            }
        }

        [TestMethod()]
        public void GetTokensFromUrl_Success_SendsClientSecretAndReturnsTokens()
        {
            int port = GetFreePort();
            HttpListener listener = StartListener(port);
            try
            {
                Task<CapturedRequest> server = StartOneShotServer(listener, 200,
                    "{\"access_token\":\"at-local\",\"expires_in\":3600,\"refresh_token\":\"rt-local\",\"token_type\":\"Bearer\"}");
                var instance = new TokenManagerService();

                TokenResponse response = instance.GetTokensFromUrl("the-code", "the-client", "the-secret",
                    "https://app.example.local/cb", "authorization_code", $"http://localhost:{port}/token", false, null);

                Assert.AreEqual("at-local", response.AccessToken);
                Assert.AreEqual("rt-local", response.RefreshToken);

                CapturedRequest captured = server.GetAwaiter().GetResult();
                StringAssert.Contains(captured.Body, "client_secret=the-secret");
                StringAssert.Contains(captured.Body, "code=the-code");
                StringAssert.Contains(captured.Body, "grant_type=authorization_code");
            }
            finally
            {
                listener.Stop();
                listener.Close();
            }
        }

        [TestMethod()]
        public void GetTokensFromUrl_OAuthError_ThrowsWithErrorDetails()
        {
            int port = GetFreePort();
            HttpListener listener = StartListener(port);
            try
            {
                Task<CapturedRequest> server = StartOneShotServer(listener, 400,
                    "{\"error\":\"invalid_grant\",\"error_description\":\"Code expired\"}");
                var instance = new TokenManagerService();

                var ex = Assert.ThrowsException<System.Net.Http.HttpRequestException>(() =>
                    instance.GetTokensFromUrl("old-code", "the-client", "the-secret",
                        "https://app.example.local/cb", "authorization_code", $"http://localhost:{port}/token", false, null));

                StringAssert.Contains(ex.Message, "400");
                StringAssert.Contains(ex.Message, "invalid_grant");
                StringAssert.Contains(ex.Message, "Code expired");
                server.GetAwaiter().GetResult();
            }
            finally
            {
                listener.Stop();
                listener.Close();
            }
        }

        [TestMethod()]
        public void GetTokensFromUrl_SecureGateway_RoutesToConfiguredHost()
        {
            int port = GetFreePort();
            HttpListener listener = StartListener(port);
            try
            {
                Task<CapturedRequest> server = StartOneShotServer(listener, 200,
                    "{\"access_token\":\"at-gateway\",\"expires_in\":60}");
                var instance = new TokenManagerService();

                WithSecureGateway("localhost", () =>
                {
                    TokenResponse response = instance.GetTokensFromUrl("code", "id", "secret",
                        "https://app.example.local/cb", "authorization_code", $"http://secure-gateway:{port}/token", false, null);
                    Assert.AreEqual("at-gateway", response.AccessToken);
                });

                server.GetAwaiter().GetResult();
            }
            finally
            {
                listener.Stop();
                listener.Close();
            }
        }
    }
}
