using Microsoft.AspNetCore.Identity;

namespace SSO_NonSSO.NETCoreWebAPI.Entities
{
    public class ApplicationUser : IdentityUser<int>
    {
        public string FirstName { get; set; }
        public string MiddleName { get; set; }
        public string LastName { get; set; }
    }
}
