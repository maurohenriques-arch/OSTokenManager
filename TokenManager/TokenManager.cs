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
        private byte[] x = { REMOVED-EC-KEY-BYTES };
        private byte[] y = { REMOVED-EC-KEY-BYTES };
        private byte[] d = { REMOVED-EC-KEY-BYTES };


        public string DecodeTokenFromPrivateKeyJWT(string encodedToken, string JWK)
        {
            Jwk jwk = Jwk.FromJson(JWK);
            string json = Jose.JWT.Decode(encodedToken, jwk);
            return json;
        }

        //public string DecodeTokenFromPrivateKeyJWT(string encodedToken)
        //{
        //    var privateKey = EcdhKey.New(x, y, d, CngKeyUsages.KeyAgreement);
        //    Jwk jwk = new Jwk(privateKey, isPrivate: true);
        //    string json = Jose.JWT.Decode(encodedToken, jwk);
        //    return json;
        //}

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

        public JWK_Pair CreateECJWKPair(string use, string crv, string kid, string algo)
        {
            JWK_Pair pair = new JWK_Pair();
            var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
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

        private Jwk createJWK(string kty, string use, string crv, string kid, string algo)
        {
            var privateKey = EcdhKey.New(x, y);
            Jwk jwk = new Jwk
            {
                Kty = kty,
                Use = use,
                Crv = crv,
                X = Convert.ToBase64String(x),
                Y = Convert.ToBase64String(y),
                D = Convert.ToBase64String(d),
                KeyId = kid,
                Alg = algo
            };
            return jwk;
        }

        private Jwk createECJWK(string kty, string use, string crv, string kid, string algo)
        {
            var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
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
                    string secureGatewayBaseURL = Environment.GetEnvironmentVariable("SECURE_GATEWAY");
                    apiURI = apiURI.Replace("secure-gateway", secureGatewayBaseURL);
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

        public string GetSecureGatewayBaseURL()
        {
            return Environment.GetEnvironmentVariable("SECURE_GATEWAY");
        }
    }
}