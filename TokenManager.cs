using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

using com.outsystems.Structures;

using Jose;
using Jose.keys;

namespace com.outsystems
{
    public class TokenManager : ITokenManager
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

        public string DecodeTokenFromPrivateKeyJWT(string encodedToken)
        {
            var privateKey = EcdhKey.New(x, y, d, CngKeyUsages.KeyAgreement);
            Jwk jwk = new Jwk(privateKey, isPrivate: true);
            string json = Jose.JWT.Decode(encodedToken, jwk);
            return json;
        }

        public string EncodeTokenFromPrivateKeyJWT(string kty, string use, string crv, string kid, string algo, List<com.outsystems.Structures.PKJWT_Claim> claims)
        {
            Jwk jwk = createJWK(kty, use, crv, kid, algo);

            string jwkString = jwk.ToJson();

            var payload = new Dictionary<string, object>();
            foreach (var c in claims)
            {
                payload.Add(c.key, c.value);
            }

            string token = Jose.JWT.Encode(payload, jwk, JweAlgorithm.ECDH_ES_A128KW, JweEncryption.A128GCM);
            return token;
        }
        public string CreatePublicJWKForEncryptionForPrivateKeyJWT(string kty, string use, string crv, string kid, string algo)
        {
            Jwk jwk = createJWK(kty, use, crv, kid, algo);
            string jwkString = jwk.ToJson();
            return jwk.ToJson();
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
        public string CreatePrivateJWKForEncryptionForPrivateKeyJWT(string kty, string use, string crv, string kid, string algo)
        {
            Jwk jwk = createJWK(kty, use, crv, kid, algo);
            string jwkString = jwk.ToJson();
            return jwk.ToJson();
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

        public string PKJWT_GetBuildInfo_Ext()
        {
            return ReadResource("com.outsystems.buildinfo.txt");
        }
    }
}