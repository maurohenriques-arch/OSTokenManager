using Microsoft.VisualStudio.TestTools.UnitTesting;
using TokenManager;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
        
        }

        [TestMethod()]
        public void CreateRSAJWKPair()
        {
            TokenManagerService instance = new TokenManagerService();
            JWK_Pair pair = instance.CreateRSAJWKPair("enc", "eueiryte87e97897", "RSA-OAEP");

        }
    }
}