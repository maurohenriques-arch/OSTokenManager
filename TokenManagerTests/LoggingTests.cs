using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TokenManager.Structures;

namespace TokenManager.Tests
{
    /// <summary>
    /// Verifies what the library logs: useful events at the right level, and never secrets,
    /// key material, claim values or provider error descriptions.
    /// </summary>
    [TestClass()]
    public class LoggingTests
    {
        private sealed class NoopScope : IDisposable
        {
            public static readonly NoopScope Instance = new NoopScope();
            public void Dispose() { }
        }

        private sealed class CapturingLogger : ILogger
        {
            public readonly List<(LogLevel Level, string Message)> Entries = new List<(LogLevel, string)>();

            public IDisposable BeginScope<TState>(TState state) where TState : notnull => NoopScope.Instance;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                Entries.Add((logLevel, formatter(state, exception)));
            }

            public bool Contains(LogLevel level, string text) =>
                Entries.Any(e => e.Level == level && e.Message.Contains(text));

            public bool AnyContains(string text) =>
                Entries.Any(e => e.Message.Contains(text));
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

        private static Task StartOneShotServer(HttpListener listener, int statusCode, string responseBody)
        {
            return Task.Run(async () =>
            {
                HttpListenerContext context = await listener.GetContextAsync();
                using (var reader = new StreamReader(context.Request.InputStream, Encoding.UTF8))
                {
                    await reader.ReadToEndAsync();
                }

                byte[] bytes = Encoding.UTF8.GetBytes(responseBody);
                context.Response.StatusCode = statusCode;
                context.Response.ContentType = "application/json";
                context.Response.ContentLength64 = bytes.Length;
                await context.Response.OutputStream.WriteAsync(bytes);
                context.Response.Close();
            });
        }

        [TestMethod()]
        public void TokenRequest_Success_LogsHostAndRefreshFlagButNoSecrets()
        {
            int port = GetFreePort();
            HttpListener listener = StartListener(port);
            try
            {
                Task server = StartOneShotServer(listener, 200,
                    "{\"access_token\":\"at-logged\",\"expires_in\":60,\"refresh_token\":\"rt-logged\"}");
                var logger = new CapturingLogger();
                var instance = new TokenManagerService(logger);

                instance.GetTokensFromUrl("the-code", "the-client", "the-secret",
                    "https://app.example.local/cb", "authorization_code", $"http://localhost:{port}/token", false, null);

                server.GetAwaiter().GetResult();
                Assert.IsTrue(logger.Contains(LogLevel.Information, "localhost"));
                Assert.IsTrue(logger.Contains(LogLevel.Information, "refresh token returned: True"));
                Assert.IsFalse(logger.AnyContains("the-secret"));
                Assert.IsFalse(logger.AnyContains("the-code"));
                Assert.IsFalse(logger.AnyContains("at-logged"));
                Assert.IsFalse(logger.AnyContains("rt-logged"));
            }
            finally
            {
                listener.Stop();
                listener.Close();
            }
        }

        [TestMethod()]
        public void TokenRequest_WithoutCertificateAndIgnoreFlag_LogsWarning()
        {
            int port = GetFreePort();
            HttpListener listener = StartListener(port);
            try
            {
                Task server = StartOneShotServer(listener, 200, "{\"access_token\":\"at-warn\",\"expires_in\":60}");
                var logger = new CapturingLogger();
                var instance = new TokenManagerService(logger);

                instance.GetTokensFromUrl("code", "id", "secret",
                    "https://app.example.local/cb", "authorization_code", $"http://localhost:{port}/token", true, null);

                server.GetAwaiter().GetResult();
                Assert.IsTrue(logger.Contains(LogLevel.Warning, "TLS certificate validation is disabled"));
            }
            finally
            {
                listener.Stop();
                listener.Close();
            }
        }

        [TestMethod()]
        public void TokenRequest_OAuthError_LogsStatusButNotProviderDescription()
        {
            int port = GetFreePort();
            HttpListener listener = StartListener(port);
            try
            {
                Task server = StartOneShotServer(listener, 400,
                    "{\"error\":\"invalid_grant\",\"error_description\":\"provider-detail-xyz\"}");
                var logger = new CapturingLogger();
                var instance = new TokenManagerService(logger);

                Assert.ThrowsException<HttpRequestException>(() =>
                    instance.GetTokensFromUrl("code", "id", "secret",
                        "https://app.example.local/cb", "authorization_code", $"http://localhost:{port}/token", false, null));

                server.GetAwaiter().GetResult();
                Assert.IsTrue(logger.Contains(LogLevel.Error, "HTTP 400"));
                Assert.IsFalse(logger.AnyContains("provider-detail-xyz"));
                Assert.IsFalse(logger.AnyContains("secret"));
            }
            finally
            {
                listener.Stop();
                listener.Close();
            }
        }

        [TestMethod()]
        public void CreateECJWKPair_LogsCurveButNotPrivateKeyMaterial()
        {
            var logger = new CapturingLogger();
            var instance = new TokenManagerService(logger);

            JWK_Pair pair = instance.CreateECJWKPair("enc", "P-384", "kid-log", "ECDH-ES+A128KW");

            using JsonDocument privateJwk = JsonDocument.Parse(pair.privateKey);
            string? d = privateJwk.RootElement.GetProperty("d").GetString();
            Assert.IsNotNull(d);
            Assert.IsTrue(logger.Contains(LogLevel.Information, "P-384"));
            Assert.IsFalse(logger.AnyContains(d));
        }
    }
}
