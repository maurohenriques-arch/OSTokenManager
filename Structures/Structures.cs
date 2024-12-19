using OutSystems.ExternalLibraries.SDK;
using Newtonsoft.Json;

namespace com.outsystems.Structures
{

    [OSStructure(Description = "Claim")]
    public struct PKJWT_Claim
    {

        [OSStructureField(DataType = OSDataType.Text, Description = "key", IsMandatory = true)]
        public string key;
        [OSStructureField(DataType = OSDataType.Text, Description = "value", IsMandatory = true)]
        public string value;
    }

}