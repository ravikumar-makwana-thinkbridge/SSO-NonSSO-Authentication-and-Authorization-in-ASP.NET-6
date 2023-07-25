using SSO_NonSSO.NETCoreWebAPI.Models;

namespace SSO_NonSSO.NETCoreWebAPI.Business
{
    public interface IUserService
    {
        Task<string> RegisterAsync(UserRegistrationRequest userRegistrationRequest);
    }
}
