using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

using TokenManager.Structures;

using Jose;
using Jose.keys;

namespace TokenManager
{
    public class TokenManagerService : ITokenManager
    {
        private byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
        private byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
        private byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };


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

        public string EncodeTokenFromPrivateKeyJWT(string kty, string use, string crv, string kid, string algo, List<TokenManager.Structures.PKJWT_Claim> claims)
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
            return ReadResource("TokenManager.buildinfo.txt");
        }
    }
}