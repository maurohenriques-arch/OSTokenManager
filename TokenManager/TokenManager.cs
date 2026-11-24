using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System;

using TokenManager.Structures;

using Jose;
using Jose.keys;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Net.Security;

namespace TokenManager
{
    public class TokenManagerService : ITokenManager
    {


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

            return Jose.JWT.Encode(payload, recipientKey, JweAlgorithm.ECDH_ES_A128KW, JweEncryption.A128GCM);
        }
        private string CreatePublicJWKForEncryptionForPrivateKeyJWT(string kty, string use, string crv, string kid, string algo)
        {
            Jwk jwk = createECJWK(kty, use, crv, kid, algo);
            string jwkString = jwk.ToJson();
            return jwk.ToJson();
        }

       
        private string CreatePrivateJWKForEncryptionForPrivateKeyJWT(string kty, string use, string crv, string kid, string algo)
        {
            Jwk jwk = createECJWK(kty, use, crv, kid, algo);
            string jwkString = jwk.ToJson();
            return jwk.ToJson();
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
            return pair;
        }

        public JWK_Pair CreateRSAJWKPair(string use, string kid, string algo)
        {
            ValidateRsaParameters(use, algo);
            JWK_Pair pair = new JWK_Pair();
            var rsa = new RSACryptoServiceProvider(2048);
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

                var response = client.Send(webRequest);
                response.EnsureSuccessStatusCode();

                string responseJson = response.Content.ReadAsStringAsync().Result;

                var jsonTokenResponse = System.Text.Json.JsonSerializer.Deserialize<JSONTokenResponse>(responseJson);
                TokenResponse tokenResponse = new TokenResponse
                {
                    AccessToken = jsonTokenResponse.AccessToken,
                    ExpiresIn = jsonTokenResponse.ExpiresIn,
                    IdToken = jsonTokenResponse.IdToken,
                    Scope = jsonTokenResponse.Scope,
                    TokenType = jsonTokenResponse.TokenType 
                };
                return tokenResponse;
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