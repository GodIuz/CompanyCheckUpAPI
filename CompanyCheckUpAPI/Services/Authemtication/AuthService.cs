using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Newtonsoft.Json;
using Google.Apis.Auth;
using System.Net;
using MailKit.Security;
using MimeKit;

namespace CompanyCheckUpAPI.Services.Authemtication
{
    public class AuthService : IAuthService
    {
        private readonly IEmailService _emailService;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _config;
        private readonly HttpClient _httpClient;

        public AuthService(
            UserManager<IdentityUser> userManager,
            IEmailService emailService,
            IConfiguration config
        )
        {
            _userManager = userManager;
            _config = config;
            _emailService = emailService;
        }


        public async Task<AuthResult> LoginAsync(string email, string password)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, password))
            {
                return FailedResult(new[] { "Invalid credentials" });
            }

            return await GenerateJwtToken(user);
        }

        public async Task<AuthResult> LoginWithFacebookAsync(string accessToken)
        {
            var fbVerifyUrl = $"https://graph.facebook.com/me?access_token={accessToken}&fields=email";
            var response = await _httpClient.GetAsync(fbVerifyUrl);

            if (!response.IsSuccessStatusCode)
            {
                return FailedResult(new[] { "Invalid Facebook token" });
            }

            var content = await response.Content.ReadAsStringAsync();
            var fbUser = JsonConvert.DeserializeObject<FacebookUser>(content);

            if (string.IsNullOrEmpty(fbUser?.Email))
            {
                return FailedResult(new[] { "Facebook email not found" });
            }

            return await CreateOrGetUser(fbUser.Email, "Facebook");
        }

        public async Task<AuthResult> LoginWithGoogleAsync(string accessToken)
        {
            try {
                var payload = await GoogleJsonWebSignature.ValidateAsync(accessToken);
                return await CreateOrGetUser(payload.Email, "Google");
            } catch {
                return FailedResult(new[] { "Invalid Google token" });
            }
        }

        public async Task<AuthResult> RegisterAsync(string email, string password)
        {
            var user = new IdentityUser { UserName = email, Email = email };
            var result = await _userManager.CreateAsync(user, password);

            if (!result.Succeeded)
            {
                return FailedResult(result.Errors.Select(e => e.Description));
            }

            return await GenerateJwtToken(user);
        }

        public async Task<AuthResult> ResetPasswordAsync(string email, string token, string newPassword)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return new AuthResult
                {
                    Success = false,
                    Errors = new[] { "Invalid request" }  // Generic error for security
                };
            }

            // Reset password
            var result = await _userManager.ResetPasswordAsync(user, token, newPassword);

            if (!result.Succeeded)
            {
                return new AuthResult
                {
                    Success = false,
                    Errors = result.Errors.Select(e => e.Description)
                };
            }

            return new AuthResult
            {
                Success = true,
                Token = null  // No JWT needed here, just success status
            };
        }

        private async Task<AuthResult> CreateOrGetUser(string email, string provider)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = new IdentityUser { UserName = email, Email = email };
                var result = await _userManager.CreateAsync(user);
                if (!result.Succeeded)
                {
                    return FailedResult(result.Errors.Select(e => e.Description));
                }

                // Add external login info
                await _userManager.AddLoginAsync(user, new UserLoginInfo(
                    provider,
                    user.Id,  // Provider key (use provider-specific ID if available)
                    provider
                ));
            }

            return await GenerateJwtToken(user);
        }

        private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
        {
            var claims = new List<Claim> {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            return new AuthResult
            {
                Success = true,
                Token = new JwtSecurityTokenHandler().WriteToken(token)
            };
        }

        private AuthResult FailedResult(IEnumerable<string> errors) => new()
        {
            Success = false,
            Errors = errors
        };

        public async Task<AuthResult> ForgotPasswordAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return new AuthResult { Success = true };

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = $"{_config["Client:ResetPasswordUrl"]}?email={email}&token={WebUtility.UrlEncode(token)}";

            // Send email via EmailService
            await _emailService.SendPasswordResetEmailAsync(email, resetLink);

            return new AuthResult { Success = true };
        }

        
    }
}
public class FacebookUser
{
    public string Id { get; set; }
    public string Email { get; set; }
}
