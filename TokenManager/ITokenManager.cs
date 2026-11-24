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

        
        [OSAction(Description = "Create an EC JWK Pair (private key and public key). Curves: P-256 (sig: ES256), P-384 (sig: ES384), P-521 (sig: ES512). Encryption (enc) algorithms: ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW.", ReturnName = "ECJWKPair")]
        public JWK_Pair CreateECJWKPair([OSParameter(Description = "Key use: sig (signing) or enc (encryption)")] string use, [OSParameter(Description = "Curve: P-256, P-384 or P-521")] string crv, string kid, [OSParameter(Description = "For sig: ES256 with P-256, ES384 with P-384, ES512 with P-521. For enc: ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW or ECDH-ES+A256KW")] string algo);

        [OSAction(Description = "Create a RSA JWK Pair (2048 bits). Use enc: RSA-OAEP, RSA-OAEP-256. Use sig: RS256, RS384, RS512, PS256, PS384, PS512.", ReturnName = "RSAJWKPair")]
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

