using OutSystems.ExternalLibraries.SDK;
using Newtonsoft.Json;
using System.Text.Json.Serialization;

namespace TokenManager.Structures
{

    [OSStructure(Description = "Claim")]
    public struct PKJWT_Claim
    {

        [OSStructureField(DataType = OSDataType.Text, Description = "key", IsMandatory = true)]
        public string key;
        [OSStructureField(DataType = OSDataType.Text, Description = "value", IsMandatory = true)]
        public string value;
    }


    [OSStructure(Description = "JWKPair")]
    public struct JWK_Pair
    {

        [OSStructureField(DataType = OSDataType.Text, Description = "privateKey", IsMandatory = true)]
        public string privateKey;
        [OSStructureField(DataType = OSDataType.Text, Description = "publicKey", IsMandatory = true)]
        public string publicKey;
    }


    [OSStructure(Description = "Response data for the Token APi Call")]
    public struct TokenResponse
    {
        [OSStructureField(DataType = OSDataType.Text, Description = "Access Token", IsMandatory = true)]
        [JsonPropertyName("access_token")]
        public string AccessToken;
        [OSStructureField(DataType = OSDataType.LongInteger, Description = "Expiration time for token", IsMandatory = true)]
        [JsonPropertyName("expires_in")]
        public long ExpiresIn;
        [OSStructureField(DataType = OSDataType.Text, Description = "Refresh Token", IsMandatory = true)]
        [JsonPropertyName("refresh_token")]
        public string RefreshToken;
        [OSStructureField(DataType = OSDataType.Text, Description = "Identity Token", IsMandatory = true)]
        [JsonPropertyName("id_token")]
        public string IdToken;
        [OSStructureField(DataType = OSDataType.Text, Description = "Token Scope", IsMandatory = false)]
        [JsonPropertyName("scope")]
        public string Scope;
        [OSStructureField(DataType = OSDataType.Text, Description = "Token Type", IsMandatory = false)]
        [JsonPropertyName("token_type")]
        public string TokenType;
    }


    public class JSONTokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }

        [JsonPropertyName("scope")]
        public string Scope { get; set; }

        [JsonPropertyName("token_type")]
        public string TokenType { get; set; }

        [JsonPropertyName("id_token")]
        public string IdToken { get; set; }
    }
}