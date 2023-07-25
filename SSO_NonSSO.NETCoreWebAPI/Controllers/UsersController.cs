using Microsoft.AspNetCore.Mvc;
using SSO_NonSSO.NETCoreWebAPI.Business;
using SSO_NonSSO.NETCoreWebAPI.Models;

namespace SSO_NonSSO.NETCoreWebAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<string>> Register(UserRegistrationRequest userRegistrationRequest)
        {
            return Ok(await _userService.RegisterAsync(userRegistrationRequest));
        }
    }
}
