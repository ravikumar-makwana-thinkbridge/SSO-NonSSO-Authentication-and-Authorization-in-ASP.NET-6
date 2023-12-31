﻿namespace SSO_NonSSO.NETCoreWebAPI.Models
{
    public class AuthenticatedUser
    {
        public string FirstName { get; set; }
        public string MiddleName { get; set; }
        public string LastName { get; set; }

        public string PhoneNumber { get; set; }
        public string Email { get; set; }

        public string AccessToken { get; set; }
    }
}
