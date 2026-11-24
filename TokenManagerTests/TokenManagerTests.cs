using Microsoft.VisualStudio.TestTools.UnitTesting;
using TokenManager;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;
using TokenManager.Structures;

namespace TokenManager.Tests
{
    [TestClass()]
    public class TokenManagerTests
    {
        [TestMethod()]
        public void DecodeTokenFromPrivateKeyJWTTest()
        {
            TokenManagerService instance = new TokenManagerService();
            string encodedToken = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJraWQiOiJlbmMtOTg0M3U5MjRoOGpmOThxamYyOTA0aiIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IngtQkZ0TVBDWTlSODRaSGVYN0JVNzFNLU1KZXZRbmZpY3gxdkJ6UEtRVGMiLCJ5Ijoia1phX2ViOHVSQlRmR0I0S2VXMUx4ZUhBZ1pwWWhzMFpRa1RTYjVLS3BOYyJ9fQ.CnSitw_58ysxMVBlvgTFUrEHUp0wnk9bLR6diRPHtQqzlJNUK5EzaQ.u4pW7gUnH53msgis.w3eWoQLPtsi_I24_Cyh8pCFPq6Bd-sog1BCJeHNR0HsbFWiJ-QAljC77wQ5RA_EkGQKIWlV23HJEP98tsmhqeqfZ8DRE4Ub-YYpp75gU4qeEVUEmK0mn2mHPr8vGQ_FzjjPPDC0p0Em77n8b0OXDsQiCJmV6Wz7Tg_Jl6uzMdJakSLN8E7dlzlSshOYB6X5eJwHNFCr2dEWG69kScQXC0gU2yNe3ornrQnJ352GccYoYAIiHH0ayHF4zNdz3XF0y_2Kd9pascrNKfqq9Jpvizk16X7LrqmIzs19hQgcH-lUe1P4gZPsVlT3BVHLcywBQHAbxwx5pAnDylUQ9lYLhndBS9ynS0BXiVeTlJR5AFU5E_N_Xl68yCLwA9zOXzePkVt4gi6LjcaJt5c9n80JJZqnK8c3gDCnvw-wgasZYuDzJAPSDZWIATaIVO7sf3BUPN5piOdXuah4s40xUjsLOLWgoL6NwV4eCgY8fxDz1EkV9wYfsToqgzZtWfGBtFSoj8j18nVCUKeiS1D7g8MXE4340K5phoomUTFxHJF1Cu0iHyR9o1v-ay0W-blsyfNfl124oO4Nbv4ba1_vzz65a5QR29CYZKZjamBd2qBr8qDXfKIKf4QvPtjvnt1ASe-AlL8Lq-nj7wm-0sXObATL2LvzZ1aev_ZV9D_9b756VgvuxStiYfTpWqO89N5i4kT8Ft2Rze-6jNnnKhVALyWIAbQIOfJbQVbUyVAuMKP9YjELgRnZ9mbufa8bvNVb_f3qkP4j35EwQmmresxxt1vOqbEXPgSJUJtkPQuoIzeI9r3YkAsnaG_mz1QWLmcCRWTbvUKlqA2MVw3V20hY.dvOp3VwpUD3z4_b_47pUXg";
            string jwks = "{ \"kty\": \"EC\",      \"use\": \"enc\",      \"crv\": \"P-256\",      \"alg\": \"ECDH-ES+A128KW\",  \"kid\": \"enc-9843u924h8jf98qjf2904j\",      \"x\": \"xVB7VKriYzeHD4xKH0fLUJqDEFK_SlNbNtvonAvErjc\",      \"y\": \"ScE1qwFquMJkzWnepZmfjcrEYFoANtS1ekcSYaJP6xs\",      \"d\": \"dFSAgZSESrca1DX6hVxDhKjGuCiHaoCIpWw9SO8GPWU\"      }";
            string decodedJWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjUxMzgzM2EyLTQ1MWYtNDE1OC04YjZiLTg4NzViNGNjMTUwOCJ9.eyJpc3MiOiJodHRwczovL3N0Zy1pZC5zaW5ncGFzcy5nb3Yuc2ciLCJzdWIiOiJ1PTg4MWFkMmVhLTAxMjgtNDI3NS05MjIwLWRkN2JjOWYxMDYwZSIsImF1ZCI6IlFqUElXN29ZeDBNYkNoWU1pNDhGalhRbTJPV0NtejNPIiwiZW1haWwiOnsibGFzdHVwZGF0ZWQiOiIyMDI1LTAxLTA4Iiwic291cmNlIjoiNCIsImNsYXNzaWZpY2F0aW9uIjoiQyIsInZhbHVlIjoibXlpbmZvdGVzdGluZ0BnbWFpbC5jb20ifSwibmFtZSI6eyJsYXN0dXBkYXRlZCI6IjIwMjUtMDEtMDgiLCJzb3VyY2UiOiIxIiwiY2xhc3NpZmljYXRpb24iOiJDIiwidmFsdWUiOiJTQU0gWUVFIn0sImlhdCI6MTczNjg1MTg3OH0.tYCEsa-MDe5dfh-GM5EgLxz-DGduMjZGiogYwpt6STfSua1rwTStmxRN1PGimixPC-YsgxLQwmMdiNz_jFYEow";
            string decoded = instance.DecodeTokenFromPrivateKeyJWT(encodedToken, jwks);
            Assert.AreEqual(decodedJWT, decoded);
        }

        [TestMethod()]
        public void CreateECJWKPair()
        {
            TokenManagerService instance = new TokenManagerService();
            JWK_Pair pair = instance.CreateECJWKPair("enc", "P-256", "eueiryte87e97897", "ECDH-ES+A128KW");

            using JsonDocument publicJwk = JsonDocument.Parse(pair.publicKey);
            using JsonDocument privateJwk = JsonDocument.Parse(pair.privateKey);
            Assert.AreEqual("EC", publicJwk.RootElement.GetProperty("kty").GetString());
            Assert.AreEqual("P-256", publicJwk.RootElement.GetProperty("crv").GetString());
            Assert.AreEqual("enc", publicJwk.RootElement.GetProperty("use").GetString());
            Assert.AreEqual("eueiryte87e97897", publicJwk.RootElement.GetProperty("kid").GetString());
            Assert.AreEqual("ECDH-ES+A128KW", publicJwk.RootElement.GetProperty("alg").GetString());
            Assert.IsFalse(publicJwk.RootElement.TryGetProperty("d", out _), "The public key must not contain d.");
            Assert.IsTrue(privateJwk.RootElement.TryGetProperty("d", out _), "The private key must contain d.");
        
        }

        [TestMethod()]
        public void EncodeThenDecodeRoundTrip()
        {
            TokenManagerService instance = new TokenManagerService();
            JWK_Pair pair = instance.CreateECJWKPair("enc", "P-256", "roundtrip-kid", "ECDH-ES+A128KW");
            var claims = new List<PKJWT_Claim>
            {
                new PKJWT_Claim { key = "sub", value = "user-1" },
                new PKJWT_Claim { key = "iss", value = "tokenmanager" }
            };

            string token = instance.EncodeTokenFromPrivateKeyJWT(pair.publicKey, claims);
            string json = instance.DecodeTokenFromPrivateKeyJWT(token, pair.privateKey);

            using JsonDocument doc = JsonDocument.Parse(json);
            Assert.AreEqual("user-1", doc.RootElement.GetProperty("sub").GetString());
            Assert.AreEqual("tokenmanager", doc.RootElement.GetProperty("iss").GetString());
        }

        [TestMethod()]
        public void EncodeRejectsPrivateKey()
        {
            TokenManagerService instance = new TokenManagerService();
            JWK_Pair pair = instance.CreateECJWKPair("enc", "P-256", "reject-kid", "ECDH-ES+A128KW");
            var claims = new List<PKJWT_Claim> { new PKJWT_Claim { key = "sub", value = "user-1" } };

            Assert.ThrowsException<ArgumentException>(() => instance.EncodeTokenFromPrivateKeyJWT(pair.privateKey, claims));
        }

        private static X509Certificate2 CreateSelfSignedCertificate(string subject)
        {
            using RSA rsa = RSA.Create(2048);
            var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        }

        [TestMethod()]
        public void ValidateServerCertificate_PinnedCertificateMatches_Accepts()
        {
            X509Certificate2 cert = CreateSelfSignedCertificate("CN=pinned");

            bool accepted = TokenManagerService.ValidateServerCertificate(cert, SslPolicyErrors.RemoteCertificateChainErrors, false, cert.RawData);

            Assert.IsTrue(accepted);
        }

        [TestMethod()]
        public void ValidateServerCertificate_PinnedCertificateDiffers_RejectsEvenWhenIgnoring()
        {
            X509Certificate2 server = CreateSelfSignedCertificate("CN=server");
            X509Certificate2 pinned = CreateSelfSignedCertificate("CN=pinned");

            bool accepted = TokenManagerService.ValidateServerCertificate(server, SslPolicyErrors.RemoteCertificateChainErrors, true, pinned.RawData);

            Assert.IsFalse(accepted);
        }

        [TestMethod()]
        public void ValidateServerCertificate_NoPin_NoErrors_Accepts()
        {
            X509Certificate2 cert = CreateSelfSignedCertificate("CN=nopin");

            bool accepted = TokenManagerService.ValidateServerCertificate(cert, SslPolicyErrors.None, false, null);

            Assert.IsTrue(accepted);
        }

        [TestMethod()]
        public void ValidateServerCertificate_NoPin_ErrorsAndNotIgnoring_Rejects()
        {
            X509Certificate2 cert = CreateSelfSignedCertificate("CN=nopin");

            bool accepted = TokenManagerService.ValidateServerCertificate(cert, SslPolicyErrors.RemoteCertificateChainErrors, false, null);

            Assert.IsFalse(accepted);
        }

        [TestMethod()]
        public void ValidateServerCertificate_NoPin_ErrorsAndIgnoring_Accepts()
        {
            X509Certificate2 cert = CreateSelfSignedCertificate("CN=nopin");

            bool accepted = TokenManagerService.ValidateServerCertificate(cert, SslPolicyErrors.RemoteCertificateChainErrors, true, null);

            Assert.IsTrue(accepted);
        }

        private static void AssertEcRoundTrip(string crv, string algo)
        {
            TokenManagerService instance = new TokenManagerService();
            JWK_Pair pair = instance.CreateECJWKPair("enc", crv, "kid-" + crv, algo);

            using JsonDocument publicJwk = JsonDocument.Parse(pair.publicKey);
            Assert.AreEqual(crv, publicJwk.RootElement.GetProperty("crv").GetString());

            var claims = new List<PKJWT_Claim> { new PKJWT_Claim { key = "sub", value = "user-" + crv } };
            string token = instance.EncodeTokenFromPrivateKeyJWT(pair.publicKey, claims);
            string json = instance.DecodeTokenFromPrivateKeyJWT(token, pair.privateKey);

            using JsonDocument doc = JsonDocument.Parse(json);
            Assert.AreEqual("user-" + crv, doc.RootElement.GetProperty("sub").GetString());
        }

        [TestMethod()]
        public void CreateECJWKPair_P384_RoundTrips()
        {
            AssertEcRoundTrip("P-384", "ECDH-ES+A128KW");
        }

        [TestMethod()]
        public void CreateECJWKPair_P521_RoundTrips()
        {
            AssertEcRoundTrip("P-521", "ECDH-ES+A128KW");
        }

        [TestMethod()]
        public void CreateECJWKPair_UnsupportedCurve_Throws()
        {
            TokenManagerService instance = new TokenManagerService();
            Assert.ThrowsException<ArgumentException>(() => instance.CreateECJWKPair("enc", "secp256k1", "kid", "ECDH-ES+A128KW"));
        }

        [TestMethod()]
        public void CreateECJWKPair_UnsupportedEncryptionAlgorithm_Throws()
        {
            TokenManagerService instance = new TokenManagerService();
            Assert.ThrowsException<ArgumentException>(() => instance.CreateECJWKPair("enc", "P-256", "kid", "RSA-OAEP"));
        }

        [TestMethod()]
        public void CreateECJWKPair_SigAlgorithmDoesNotMatchCurve_Throws()
        {
            TokenManagerService instance = new TokenManagerService();
            Assert.ThrowsException<ArgumentException>(() => instance.CreateECJWKPair("sig", "P-384", "kid", "ES256"));
        }

        [TestMethod()]
        public void CreateECJWKPair_InvalidUse_Throws()
        {
            TokenManagerService instance = new TokenManagerService();
            Assert.ThrowsException<ArgumentException>(() => instance.CreateECJWKPair("both", "P-256", "kid", "ECDH-ES+A128KW"));
        }

        [TestMethod()]
        public void CreateRSAJWKPair_SignatureAlgorithm_Accepts()
        {
            TokenManagerService instance = new TokenManagerService();
            JWK_Pair pair = instance.CreateRSAJWKPair("sig", "kid", "RS256");
            Assert.IsNotNull(pair.publicKey);
        }

        [TestMethod()]
        public void CreateRSAJWKPair_UnsupportedAlgorithm_Throws()
        {
            TokenManagerService instance = new TokenManagerService();
            Assert.ThrowsException<ArgumentException>(() => instance.CreateRSAJWKPair("enc", "kid", "ES256"));
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
        public void SecureGateway_NotSet_Throws()
        {
            TokenManagerService instance = new TokenManagerService();
            WithSecureGateway(null, () =>
                Assert.ThrowsException<InvalidOperationException>(() => instance.GetSecureGatewayBaseURL()));
        }

        [TestMethod()]
        public void SecureGateway_WithScheme_Throws()
        {
            TokenManagerService instance = new TokenManagerService();
            WithSecureGateway("https://gw.example.local", () =>
                Assert.ThrowsException<InvalidOperationException>(() => instance.GetSecureGatewayBaseURL()));
        }

        [TestMethod()]
        public void SecureGateway_WithPort_Throws()
        {
            TokenManagerService instance = new TokenManagerService();
            WithSecureGateway("gw.example.local:8080", () =>
                Assert.ThrowsException<InvalidOperationException>(() => instance.GetSecureGatewayBaseURL()));
        }

        [TestMethod()]
        public void SecureGateway_HostName_Returns()
        {
            TokenManagerService instance = new TokenManagerService();
            WithSecureGateway("gw.example.local", () =>
                Assert.AreEqual("gw.example.local", instance.GetSecureGatewayBaseURL()));
        }

        [TestMethod()]
        public void GetTokensFromUrl_SecureGatewayNotSet_ThrowsBeforeNetworkCall()
        {
            TokenManagerService instance = new TokenManagerService();
            WithSecureGateway(null, () =>
                Assert.ThrowsException<InvalidOperationException>(() =>
                    instance.GetTokensFromUrl("code", "id", "secret", "https://example.local/cb", "authorization_code", "https://secure-gateway:8080/token", false, null)));
        }

        [TestMethod()]
        public void ParseTokenResponse_Success_MapsAllFields()
        {
            string body = "{\"access_token\":\"at-1\",\"expires_in\":3600,\"refresh_token\":\"rt-1\",\"id_token\":\"id-1\",\"scope\":\"openid profile\",\"token_type\":\"Bearer\"}";

            TokenResponse response = TokenManagerService.ParseTokenResponse(HttpStatusCode.OK, body);

            Assert.AreEqual("at-1", response.AccessToken);
            Assert.AreEqual(3600, response.ExpiresIn);
            Assert.AreEqual("rt-1", response.RefreshToken);
            Assert.AreEqual("id-1", response.IdToken);
            Assert.AreEqual("openid profile", response.Scope);
            Assert.AreEqual("Bearer", response.TokenType);
        }

        [TestMethod()]
        public void ParseTokenResponse_Success_WithoutRefreshToken_LeavesItEmpty()
        {
            TokenResponse response = TokenManagerService.ParseTokenResponse(HttpStatusCode.OK, "{\"access_token\":\"at-2\",\"expires_in\":60}");

            Assert.AreEqual("at-2", response.AccessToken);
            Assert.IsNull(response.RefreshToken);
        }

        [TestMethod()]
        public void ParseTokenResponse_OAuthError_IncludesErrorAndDescription()
        {
            string body = "{\"error\":\"invalid_grant\",\"error_description\":\"Code expired\"}";

            var ex = Assert.ThrowsException<HttpRequestException>(() =>
                TokenManagerService.ParseTokenResponse(HttpStatusCode.BadRequest, body));

            StringAssert.Contains(ex.Message, "400");
            StringAssert.Contains(ex.Message, "invalid_grant");
            StringAssert.Contains(ex.Message, "Code expired");
        }

        [TestMethod()]
        public void ParseTokenResponse_NonJsonErrorBody_ReportsStatusOnly()
        {
            var ex = Assert.ThrowsException<HttpRequestException>(() =>
                TokenManagerService.ParseTokenResponse(HttpStatusCode.BadGateway, "<html>internal-detail</html>"));

            StringAssert.Contains(ex.Message, "502");
            Assert.IsFalse(ex.Message.Contains("internal-detail"));
        }

        [TestMethod()]
        public void ParseTokenResponse_InvalidJson_Throws()
        {
            Assert.ThrowsException<InvalidOperationException>(() =>
                TokenManagerService.ParseTokenResponse(HttpStatusCode.OK, "not json"));
        }

        [TestMethod()]
        public void ParseTokenResponse_NullJson_Throws()
        {
            Assert.ThrowsException<InvalidOperationException>(() =>
                TokenManagerService.ParseTokenResponse(HttpStatusCode.OK, "null"));
        }

        [TestMethod()]
        public void ParseTokenResponse_MissingAccessToken_Throws()
        {
            Assert.ThrowsException<InvalidOperationException>(() =>
                TokenManagerService.ParseTokenResponse(HttpStatusCode.OK, "{\"token_type\":\"Bearer\"}"));
        }

        [TestMethod()]
        public void CreateRSAJWKPair()
        {
            TokenManagerService instance = new TokenManagerService();
            JWK_Pair pair = instance.CreateRSAJWKPair("enc", "eueiryte87e97897", "RSA-OAEP");

            using JsonDocument publicJwk = JsonDocument.Parse(pair.publicKey);
            using JsonDocument privateJwk = JsonDocument.Parse(pair.privateKey);
            Assert.AreEqual("RSA", publicJwk.RootElement.GetProperty("kty").GetString());
            Assert.AreEqual("enc", publicJwk.RootElement.GetProperty("use").GetString());
            Assert.AreEqual("RSA-OAEP", publicJwk.RootElement.GetProperty("alg").GetString());
            Assert.IsTrue(publicJwk.RootElement.TryGetProperty("n", out _));
            Assert.IsTrue(publicJwk.RootElement.TryGetProperty("e", out _));
            Assert.IsFalse(publicJwk.RootElement.TryGetProperty("d", out _), "The public key must not contain d.");
            Assert.IsTrue(privateJwk.RootElement.TryGetProperty("d", out _), "The private key must contain d.");

        }

        [TestMethod()]
        [TestCategory("Integration")]
        public void GetTokensFromUrlTest()
        {
            if (Environment.GetEnvironmentVariable("TOKENMANAGER_INTEGRATION_TESTS") != "1")
            {
                Assert.Inconclusive("Set TOKENMANAGER_INTEGRATION_TESTS=1 to run the live token endpoint test.");
            }

            TokenManagerService tms = new TokenManagerService();

            string code = "";
            string clientId = "";
            string clientSecret = "";
            string redirectUri = "https://professionalservices-dev.outsystems.app/ODCAuthBroker/rest/OutboundOIDCAPI/oauth2callback";
            string grantType = "authorization_code";
            string apiURL = "https://oauth2.googleapis.com/token";
            bool ignoreCertificateValidation = true;
            byte[]? certificateToAllow = null;

            var response = tms.GetTokensFromUrl(code, clientId, clientSecret, redirectUri, grantType, apiURL, ignoreCertificateValidation, certificateToAllow);

            Assert.IsNotNull(response);
        }
    }
}