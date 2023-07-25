using Microsoft.AspNetCore.Mvc;
using SSO_NonSSO.NETCoreWebAPI.Business;
using SSO_NonSSO.NETCoreWebAPI.Models;

namespace SSO_NonSSO.NETCoreWebAPI.Controllers
{
    [ApiController]
    [Route("authenticate")]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthenticationService _authenticationService;

        public AuthenticationController(IAuthenticationService authenticationService)
        {
            _authenticationService = authenticationService;
        }

        [HttpPost]
        public async Task<ActionResult<AuthenticatedUser>> AuthenticateAsync(LoginRequest loginRequest)
        {
            return Ok(await _authenticationService.AuthenticateAsync(loginRequest));
        }

        [HttpPost("~/api/auth-callback")]
        public async Task<ActionResult<AuthenticatedUser>> AuthCallbackAsync(TokenRequest tokenRequest)
        {
            return Ok(await _authenticationService.AuthenticateAsync(tokenRequest));
        }
    }
}
