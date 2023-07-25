using AutoMapper;
using SSO_NonSSO.NETCoreWebAPI.Entities;
using SSO_NonSSO.NETCoreWebAPI.Models;

namespace SSO_NonSSO.NETCoreWebAPI.Profiles
{
    public class ApplicationUserProfile : Profile
    {
        public ApplicationUserProfile()
        {
            CreateMap<ApplicationUser, AuthenticatedUser>();

            CreateMap<UserRegistrationRequest, ApplicationUser>();
        }
    }
}
