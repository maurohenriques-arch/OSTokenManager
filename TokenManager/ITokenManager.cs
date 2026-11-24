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

        [OSAction(Description = "Encode a token in a JWE for a recipient, using the recipient's public EC JWK", ReturnName = "encodedToken")]
        public string EncodeTokenFromPrivateKeyJWT(string recipientPublicJWK, List<TokenManager.Structures.PKJWT_Claim> claims);

        
        [OSAction(Description = "Create an EC JWK Pair (private key and public key)", ReturnName = "ECJWKPair")]
        public JWK_Pair CreateECJWKPair([OSParameter(Description = "For signing the value = sig. For Encryption the value = enc")] string use, [OSParameter(Description = "Curve type of the key, usualy P-256")] string crv, string kid, [OSParameter(Description = "Signing and Encryption have diferent algorithms. For SingPass Encryption it must be at least ECDH-ES+A128KW")] string algo);

        [OSAction(Description = "Create a RSA JWK Pair", ReturnName = "RSAJWKPair")]
        public JWK_Pair CreateRSAJWKPair(string use, string kid, string algo);

        /// <summary>
        /// Retrieve unique build information of this custom library.
        /// </summary>
        [OSAction(Description = "Get unique build information of this custom library.", ReturnName = "buildInfo")]
        public string PKJWT_GetBuildInfo_Ext();

        /// <summary>
        /// Calls the token endpoint over HTTPS with a POST request.
        /// If certificateToAllow is supplied, the server certificate must match it exactly and
        /// ignoreCertificateValidation has no effect. Otherwise, certificate errors are ignored
        /// only when ignoreCertificateValidation is true, which disables server certificate validation.
        /// </summary>
        [OSAction(Description = "Call POST token REST service over HTTPS. If certificateToAllow is supplied, the server certificate must match it; otherwise certificate errors are ignored only when ignoreCertificateValidation is true.", ReturnName = "TokenResponse")]
        public TokenResponse GetTokensFromUrl(
            [OSParameter(DataType = OSDataType.Text)]
            string code,
            [OSParameter(DataType = OSDataType.Text)]
            string clientId,
            [OSParameter(DataType = OSDataType.Text)]
            string clientSecret,
            [OSParameter(DataType = OSDataType.Text)]
            string redirectUri,
            [OSParameter(DataType = OSDataType.Text)]
            string grantType,
            [OSParameter(DataType = OSDataType.Text)]
            string apiURI,
            [OSParameter(DataType = OSDataType.Boolean)]
            bool ignoreCertificateValidation,
            byte[] certificateToAllow = null
            );

        [OSAction(Description = "Get the External Library generated Secure Gateway URL", ReturnName = "URL")]
        public string GetSecureGatewayBaseURL();


    }
}

