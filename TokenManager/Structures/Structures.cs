using OutSystems.ExternalLibraries.SDK;
using Newtonsoft.Json;

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

}