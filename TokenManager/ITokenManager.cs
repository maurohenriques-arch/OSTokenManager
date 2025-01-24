using OutSystems.ExternalLibraries.SDK;
using TokenManager.Structures;


namespace TokenManager
{    /// <summary>
     /// The IPrivateKeyJWT_Ext interface defines the methods (exposed as server actions) for Singpass utilities
     /// </summary>
    [OSInterface(Description = "Private key management custom code extension library.", Name = "TokenManager", IconResourceName = "TokenManager.PrivateKeyJWTIcon.png")]
    public interface ITokenManager
    {
        [OSAction(Description = "Decode an encoded token in a JWE based on a JSON JWK", ReturnName = "decodedToken")]
        public string DecodeTokenFromPrivateKeyJWT(string encodedToken, string JWK);

        //[OSAction(Description = "Decode an encoded token in a JWE", ReturnName = "decodedToken")]
        //public string DecodeTokenFromPrivateKeyJWT(string encodedToken);

        [OSAction(Description = "Encode a token in a JWE", ReturnName = "encodedToken")]
        public string EncodeTokenFromPrivateKeyJWT(string kty, string use, string crv, string kid, string algo, List<TokenManager.Structures.PKJWT_Claim> claims);

        [OSAction(Description = "Create a public JWK for encryption", ReturnName = "publicKey")]
        public string CreatePublicJWKForEncryptionForPrivateKeyJWT(string kty, string use, string crv, string kid, string algo);

        [OSAction(Description = "Create a private JWK for encryption", ReturnName = "privateKey")]
        public string CreatePrivateJWKForEncryptionForPrivateKeyJWT(string kty, string use, string crv, string kid, string algo);

        /// <summary>
        /// Retrieve unique build information of this custom library.
        /// </summary>
        [OSAction(Description = "Get unique build information of this custom library.", ReturnName = "buildInfo")]
        public string PKJWT_GetBuildInfo_Ext();


    }
}

