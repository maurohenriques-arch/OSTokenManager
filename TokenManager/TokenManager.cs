using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System;

using TokenManager.Structures;

using Jose;
using System.Net;
using System.Net.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace TokenManager
{
    public class TokenManagerService : ITokenManager
    {
        private readonly ILogger _logger;

        /// <summary>
        /// Creates the service with a logger supplied by the ODC host.
        /// </summary>
        public TokenManagerService(ILogger logger)
        {
            _logger = logger ?? NullLogger.Instance;
        }

        /// <summary>
        /// Creates the service without logging.
        /// </summary>
        public TokenManagerService() : this(NullLogger.Instance)
        {
        }

        private static string GetHostForLog(string uri)
        {
            return Uri.TryCreate(uri, UriKind.Absolute, out Uri parsed) ? parsed.Host : "(invalid URL)";
        }



        public string DecodeTokenFromPrivateKeyJWT(string encodedToken, string JWK)
        {
            Jwk jwk = Jwk.FromJson(JWK);
            string json = Jose.JWT.Decode(encodedToken, jwk);
            return json;
        }


        public string EncodeTokenFromPrivateKeyJWT(string recipientPublicJWK, List<TokenManager.Structures.PKJWT_Claim> claims)
        {
            Jwk recipientKey = Jwk.FromJson(recipientPublicJWK);
            if (recipientKey.D != null)
            {
                throw new ArgumentException("recipientPublicJWK must contain the public key only; remove the private part (d).");
            }

            var payload = new Dictionary<string, object>();
            foreach (var c in claims)
            {
                payload.Add(c.key, c.value);
            }

            _logger.LogInformation("Encoded JWE with {ClaimCount} claims", claims.Count);
            return Jose.JWT.Encode(payload, recipientKey, JweAlgorithm.ECDH_ES_A128KW, JweEncryption.A128GCM);
        }
       
        private static readonly string[] EcEncryptionAlgorithms = { "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW" };
        private static readonly string[] RsaEncryptionAlgorithms = { "RSA-OAEP", "RSA-OAEP-256" };
        private static readonly string[] RsaSignatureAlgorithms = { "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" };

        private static void ValidateUse(string use)
        {
            if (use != "enc" && use != "sig")
            {
                throw new ArgumentException($"Unsupported use '{use}'. Supported values: enc, sig.", nameof(use));
            }
        }

        /// <summary>
        /// Validates the EC parameters and returns the matching curve.
        /// Supported curves: P-256 (ES256), P-384 (ES384), P-521 (ES512) for signing;
        /// ECDH-ES family for encryption.
        /// </summary>
        private static ECCurve ValidateEcParameters(string use, string crv, string algo)
        {
            ValidateUse(use);

            ECCurve curve;
            string signatureAlgorithm;
            switch (crv)
            {
                case "P-256":
                    curve = ECCurve.NamedCurves.nistP256;
                    signatureAlgorithm = "ES256";
                    break;
                case "P-384":
                    curve = ECCurve.NamedCurves.nistP384;
                    signatureAlgorithm = "ES384";
                    break;
                case "P-521":
                    curve = ECCurve.NamedCurves.nistP521;
                    signatureAlgorithm = "ES512";
                    break;
                default:
                    throw new ArgumentException($"Unsupported EC curve '{crv}'. Supported curves: P-256, P-384, P-521.", nameof(crv));
            }

            if (use == "sig" && algo != signatureAlgorithm)
            {
                throw new ArgumentException($"For curve {crv} and use sig the algorithm must be {signatureAlgorithm}.", nameof(algo));
            }

            if (use == "enc" && !EcEncryptionAlgorithms.Contains(algo))
            {
                throw new ArgumentException($"Unsupported EC encryption algorithm '{algo}'. Supported: {string.Join(", ", EcEncryptionAlgorithms)}.", nameof(algo));
            }

            return curve;
        }

        private static void ValidateRsaParameters(string use, string algo)
        {
            ValidateUse(use);

            string[] allowed = use == "enc" ? RsaEncryptionAlgorithms : RsaSignatureAlgorithms;
            if (!allowed.Contains(algo))
            {
                throw new ArgumentException($"Unsupported RSA algorithm '{algo}' for use {use}. Supported: {string.Join(", ", allowed)}.", nameof(algo));
            }
        }

        public JWK_Pair CreateECJWKPair(string use, string crv, string kid, string algo)
        {
            ECCurve curve = ValidateEcParameters(use, crv, algo);
            JWK_Pair pair = new JWK_Pair();
            var ecdsa = ECDsa.Create(curve);
            var privateKey = ecdsa.ExportParameters(true);
            var publicKey = ecdsa.ExportParameters(false);
            Jwk prvwk = new Jwk
            {
                Kty = "EC",
                Use = use,
                Crv = crv,
                X = Base64Url.Encode(publicKey.Q.X),
                Y = Base64Url.Encode(publicKey.Q.Y),
                D = Base64Url.Encode(privateKey.D),
                KeyId = kid,
                Alg = algo
            };
            Jwk pubJwk = new Jwk
            {
                Kty = "EC",
                Use = use,
                Crv = crv,
                X = Base64Url.Encode(publicKey.Q.X),
                Y = Base64Url.Encode(publicKey.Q.Y),
                KeyId = kid,
                Alg = algo
            };
            pair.publicKey = pubJwk.ToJson();
            pair.privateKey = prvwk.ToJson();
            _logger.LogInformation("Generated EC key pair for use {Use} on curve {Curve}", use, crv);
            return pair;
        }

        public JWK_Pair CreateRSAJWKPair(string use, string kid, string algo)
        {
            ValidateRsaParameters(use, algo);
            JWK_Pair pair = new JWK_Pair();
            var rsa = RSA.Create(2048);
            var privateKey = rsa.ExportParameters(true);
            var publicKey = rsa.ExportParameters(false);

            Jwk prvwk = new Jwk
            {
                Kty = "RSA",
                Use = use,
                N = Base64Url.Encode(publicKey.Modulus),
                E = Base64Url.Encode(publicKey.Exponent),
                D = Base64Url.Encode(privateKey.D),
                P = Base64Url.Encode(privateKey.P),
                Q = Base64Url.Encode(privateKey.Q),
                DP = Base64Url.Encode(privateKey.DP),
                DQ = Base64Url.Encode(privateKey.DQ),
                QI = Base64Url.Encode(privateKey.InverseQ),
                KeyId = kid,
                Alg = algo
            };

            Jwk pubJwk = new Jwk
            {
                Kty = "RSA",
                Use = use,
                N = Base64Url.Encode(publicKey.Modulus),
                E = Base64Url.Encode(publicKey.Exponent),
                KeyId = kid,
                Alg = algo
            };

            pair.publicKey = pubJwk.ToJson();
            pair.privateKey = prvwk.ToJson();
            _logger.LogInformation("Generated RSA key pair for use {Use}", use);

            return pair;
        }



        public string PKJWT_GetBuildInfo_Ext()
        {
            return ReadResource("TokenManager.buildinfo.txt");
        }

        private Jwk createECJWK(string kty, string use, string crv, string kid, string algo)
        {
            ECCurve curve = ValidateEcParameters(use, crv, algo);
            var ecdsa = ECDsa.Create(curve);
            var privateKey = ecdsa.ExportParameters(true);
            var publicKey = ecdsa.ExportParameters(false);
            Jwk jwk = new Jwk
            {
                Kty = kty,
                Use = use,
                Crv = crv,
                X = Base64Url.Encode(publicKey.Q.X),
                Y = Base64Url.Encode(publicKey.Q.Y),
                D = Base64Url.Encode(privateKey.D),
                KeyId = kid,
                Alg = algo
            };
            return jwk;
        }

        private string ReadResource(string name)
        {
            var assembly = Assembly.GetExecutingAssembly();
            string resourcePath = name;
            if (assembly.GetManifestResourceStream(resourcePath) != null)
            {
                using (Stream stream = assembly.GetManifestResourceStream(resourcePath)!)
                {
                    using (StreamReader reader = new StreamReader(stream))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }
            //
            return string.Empty;
        }

        /// <summary>
        /// Decides whether a server certificate is accepted.
        /// If <paramref name="certificateToAllow"/> is supplied, the server certificate must be
        /// byte-for-byte equal to it and <paramref name="ignoreCertificateValidation"/> has no effect.
        /// Otherwise, certificate errors are ignored only when <paramref name="ignoreCertificateValidation"/> is true.
        /// </summary>
        public static bool ValidateServerCertificate(
            X509Certificate2 serverCertificate,
            SslPolicyErrors sslPolicyErrors,
            bool ignoreCertificateValidation,
            byte[] certificateToAllow)
        {
            if (certificateToAllow != null && certificateToAllow.Length > 0)
            {
                return serverCertificate != null && serverCertificate.RawData.SequenceEqual(certificateToAllow);
            }

            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true;
            }

            return ignoreCertificateValidation;
        }

        /// <summary>
        /// Turns a token endpoint response into a TokenResponse.
        /// Non-success statuses raise HttpRequestException with the HTTP status and any OAuth
        /// error and error_description. Invalid or empty bodies, and bodies without access_token,
        /// raise InvalidOperationException. The refresh_token is returned when the provider sends it.
        /// </summary>
        public static TokenResponse ParseTokenResponse(HttpStatusCode statusCode, string responseBody)
        {
            if (!((int)statusCode >= 200 && (int)statusCode <= 299))
            {
                throw new HttpRequestException(BuildTokenErrorMessage(statusCode, responseBody));
            }

            JSONTokenResponse jsonTokenResponse;
            try
            {
                jsonTokenResponse = System.Text.Json.JsonSerializer.Deserialize<JSONTokenResponse>(responseBody ?? string.Empty);
            }
            catch (System.Text.Json.JsonException ex)
            {
                throw new InvalidOperationException("The token endpoint returned a response that is not valid JSON.", ex);
            }

            if (jsonTokenResponse == null || string.IsNullOrWhiteSpace(jsonTokenResponse.AccessToken))
            {
                throw new InvalidOperationException("The token endpoint response does not contain an access_token.");
            }

            return new TokenResponse
            {
                AccessToken = jsonTokenResponse.AccessToken,
                ExpiresIn = jsonTokenResponse.ExpiresIn,
                RefreshToken = jsonTokenResponse.RefreshToken,
                IdToken = jsonTokenResponse.IdToken,
                Scope = jsonTokenResponse.Scope,
                TokenType = jsonTokenResponse.TokenType
            };
        }

        private static string BuildTokenErrorMessage(HttpStatusCode statusCode, string responseBody)
        {
            var message = new StringBuilder();
            message.Append($"Token endpoint returned HTTP {(int)statusCode} ({statusCode}).");

            try
            {
                using JsonDocument document = JsonDocument.Parse(responseBody ?? string.Empty);
                if (document.RootElement.ValueKind == JsonValueKind.Object)
                {
                    string error = ReadStringProperty(document.RootElement, "error");
                    string description = ReadStringProperty(document.RootElement, "error_description");

                    if (error != null)
                    {
                        message.Append($" error: {error}.");
                    }

                    if (description != null)
                    {
                        const int maxLength = 500;
                        string trimmed = description.Length > maxLength ? description.Substring(0, maxLength) + "..." : description;
                        message.Append($" error_description: {trimmed}");
                    }
                }
            }
            catch (System.Text.Json.JsonException)
            {
                // The body is not JSON: report only the HTTP status, never the raw body.
            }

            return message.ToString();
        }

        private static string ReadStringProperty(JsonElement element, string name)
        {
            return element.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
        }

        public TokenResponse GetTokensFromUrl(
            string code,
            string clientId,
            string clientSecret,
            string redirectUri,
            string grantType,
            string apiURI,
            bool ignoreCertificateValidation,
            byte[] certificateToAllow = null
            )
        {
            var handler = new HttpClientHandler();
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ServerCertificateCustomValidationCallback =
                (httpRequestMessage, cert, cetChain, sslPolicyErrors) =>
                    ValidateServerCertificate(cert, sslPolicyErrors, ignoreCertificateValidation, certificateToAllow);

            using (HttpClient client = new HttpClient(handler))
            {
                var formData = new Dictionary<string, string>
                {
                    {"code", code},
                    {"client_id", clientId},
                    {"client_secret", clientSecret},
                    {"redirect_uri", redirectUri},
                    {"grant_type", grantType}
                };
                var content = new FormUrlEncodedContent(formData);

                if (apiURI.Contains("secure-gateway"))
                {
                    apiURI = apiURI.Replace("secure-gateway", GetSecureGatewayHost());
                }

                var webRequest = new HttpRequestMessage(HttpMethod.Post, apiURI)
                {
                    Content = content
                };

                string host = GetHostForLog(apiURI);
                _logger.LogInformation("Requesting token from {Host}", host);

                if (ignoreCertificateValidation && (certificateToAllow == null || certificateToAllow.Length == 0))
                {
                    _logger.LogWarning("TLS certificate validation is disabled for {Host}: no certificate was supplied", host);
                }

                HttpResponseMessage response;
                try
                {
                    response = client.SendAsync(webRequest).GetAwaiter().GetResult();
                }
                catch (HttpRequestException ex)
                {
                    _logger.LogError("Token request to {Host} failed before a response was received: {ExceptionType}", host, ex.GetType().Name);
                    throw;
                }

                string responseBody = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                try
                {
                    TokenResponse tokenResponse = ParseTokenResponse(response.StatusCode, responseBody);
                    _logger.LogInformation("Token response from {Host}: HTTP {StatusCode}, refresh token returned: {RefreshTokenReturned}",
                        host, (int)response.StatusCode, !string.IsNullOrEmpty(tokenResponse.RefreshToken));
                    return tokenResponse;
                }
                catch (Exception ex) when (ex is HttpRequestException || ex is InvalidOperationException)
                {
                    _logger.LogError("Token request to {Host} failed with HTTP {StatusCode}: {ExceptionType}",
                        host, (int)response.StatusCode, ex.GetType().Name);
                    throw;
                }
            }
        }

        /// <summary>
        /// Returns the Secure Gateway host from the SECURE_GATEWAY environment variable.
        /// The value must be a host name only (no scheme, path or port); the port is set in the URL.
        /// Throws InvalidOperationException when the variable is missing or invalid.
        /// </summary>
        private static string GetSecureGatewayHost()
        {
            string host = Environment.GetEnvironmentVariable("SECURE_GATEWAY");

            if (string.IsNullOrWhiteSpace(host))
            {
                throw new InvalidOperationException("The SECURE_GATEWAY environment variable is not set. Set it to the Secure Gateway host name.");
            }

            if (!Regex.IsMatch(host, @"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$"))
            {
                throw new InvalidOperationException($"The SECURE_GATEWAY environment variable '{host}' is not a valid host name. Use the host name only, without scheme, path or port.");
            }

            return host;
        }

        public string GetSecureGatewayBaseURL()
        {
            return GetSecureGatewayHost();
        }
    }
}