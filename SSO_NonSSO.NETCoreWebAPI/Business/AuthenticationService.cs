using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using RestSharp;
using SSO_NonSSO.NETCoreWebAPI.Entities;
using SSO_NonSSO.NETCoreWebAPI.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace SSO_NonSSO.NETCoreWebAPI.Business
{
    public class AuthenticationService : IAuthenticationService
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IMapper _mapper;

        public AuthenticationService(UserManager<ApplicationUser> userManager, IMapper mapper)
        {
            _userManager = userManager;
            _mapper = mapper;
        }

        public async Task<AuthenticatedUser> AuthenticateAsync(LoginRequest loginRequest)
        {
            var user = await _userManager.FindByEmailAsync(loginRequest.EmailAddress);
            await ValidateUserCredentialsAsync(user, loginRequest);

            var authenticatedUser = _mapper.Map<AuthenticatedUser>(user);
            authenticatedUser.AccessToken = GenerateAccessToken(user);

            return authenticatedUser;
        }

        private string GenerateAccessToken(ApplicationUser user)
        {
            var claims = GetUserClaims(user);

            var handler = new JwtSecurityTokenHandler();

            var signingCredentials = new SigningCredentials(
                new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes("JWTRefreshTokenHIGHsecuredPasswordVVVp1OH7Xzyr")),
                    SecurityAlgorithms.HmacSha256
                    );

            var securityToken =
                new JwtSecurityToken(
                    "https://localhost:7112",
                    "https://localhost:7112",
                    claims,
                    DateTime.Now,
                    expires: DateTime.Now.AddMinutes(10),
                    signingCredentials);

            return handler.WriteToken(securityToken);
        }

        private List<Claim> GetUserClaims(ApplicationUser user)
        {
            return new List<Claim>
            {
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.MobilePhone, user.PhoneNumber),
                new Claim(ClaimTypes.Name, user.UserName)
            };
        }

        private async Task ValidateUserCredentialsAsync(ApplicationUser user, LoginRequest loginRequest)
        {
            if (user == null)
            {
                throw new InvalidOperationException($"User doesn't exists for given email address: {loginRequest.EmailAddress}.");
            }

            bool isPasswordValide = await _userManager.CheckPasswordAsync(user, loginRequest.Password);

            if (!isPasswordValide)
            {
                throw new InvalidOperationException("Invalid Password, Please enter your correct password.");
            }
        }

        public async Task<AuthenticatedUser> AuthenticateAsync(TokenRequest tokenRequest)
        {
            var clientId = "<Client Id>";
            var clientSecret = "<Client Secret>";
            var tenantId = "<Tenant Id>";
            var scope = "<Scope>";

            var options = new RestClientOptions("https://login.microsoftonline.com")
            {
                MaxTimeout = -1,
            };
            var client = new RestClient(options);
            var request = new RestRequest($"/{tenantId}/oauth2/v2.0/token", Method.Post);
            request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
            request.AddParameter("client_id", clientId);
            request.AddParameter("scope", scope);
            request.AddParameter("code", tokenRequest.Code);
            request.AddParameter("redirect_uri", tokenRequest.RedirectURI);
            request.AddParameter("grant_type", "authorization_code");
            request.AddParameter("client_secret", clientSecret);
            var response = await client.ExecuteAsync(request);
            
            var tokenResponseModel = JsonSerializer.Deserialize<TokenResponseModel>(response?.Content);
            var token = new JwtSecurityToken(tokenResponseModel?.AccessToken);
            var emailAddress = token.Claims.First(c => c.Type == "upn").Value;

            var user = await _userManager.FindByEmailAsync(emailAddress);

            var authenticatedUser = _mapper.Map<AuthenticatedUser>(user);
            authenticatedUser.AccessToken = GenerateAccessToken(user);

            return authenticatedUser;
        }
    }
}
