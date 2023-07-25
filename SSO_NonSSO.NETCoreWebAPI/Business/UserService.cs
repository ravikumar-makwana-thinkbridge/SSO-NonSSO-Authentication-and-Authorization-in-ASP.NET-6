using AutoMapper;
using Microsoft.AspNetCore.Identity;
using SSO_NonSSO.NETCoreWebAPI.Entities;
using SSO_NonSSO.NETCoreWebAPI.Models;

namespace SSO_NonSSO.NETCoreWebAPI.Business
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IMapper _mapper;

        public UserService(UserManager<ApplicationUser> userManager, IMapper mapper)
        {
            _userManager = userManager;
            _mapper = mapper;
        }

        public async Task<string> RegisterAsync(UserRegistrationRequest userRegistrationRequest)
        {
            var existingUser = await _userManager.FindByEmailAsync(userRegistrationRequest.Email);

            if (existingUser != null)
            {
                throw new InvalidOperationException($"User already exists with given email address : {userRegistrationRequest.Email}");
            }

            var user = _mapper.Map<ApplicationUser>(userRegistrationRequest);
            var result = await _userManager.CreateAsync(user, userRegistrationRequest.Password);

            return result.Succeeded ? "Registration Successful" : "Registration Failed";
        }
    }
}
