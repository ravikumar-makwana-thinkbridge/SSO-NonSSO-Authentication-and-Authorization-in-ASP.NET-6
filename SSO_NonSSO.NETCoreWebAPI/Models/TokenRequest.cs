namespace SSO_NonSSO.NETCoreWebAPI.Models
{
    public class TokenRequest
    {
        public string Code { get; set; }
        public string RedirectURI { get; set; }
    }
}