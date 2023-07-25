using SSO_NonSSO.NETCoreWebAPI.Entities;
using SSO_NonSSO.NETCoreWebAPI.Models;

namespace SSO_NonSSO.NETCoreWebAPI.Business
{
    public interface IAuthenticationService
    {
        Task<AuthenticatedUser> AuthenticateAsync(LoginRequest loginRequest);
        Task<AuthenticatedUser> AuthenticateAsync(TokenRequest tokenRequest);
    }
}
