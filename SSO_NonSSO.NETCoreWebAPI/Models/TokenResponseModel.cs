using System.Text.Json.Serialization;

namespace SSO_NonSSO.NETCoreWebAPI.Models
{
    public class TokenResponseModel
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }
    }
}
