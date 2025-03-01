using CompanyCheckUpAPI.Controllers;
using CompanyCheckUpAPI.Data;
using CompanyCheckUpAPI.Model;
using Google.Apis.Auth.OAuth2.Requests;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Generators;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace CompanyCheckUpAPI.Services.Authemtication
{
    public class UserService : IUserService
    {
        private readonly ILogger<UserService> _logger;
        private readonly AppDbContext _context;
        private readonly JwtSettings _jwtSettings;

        public UserService(
            ILogger<UserService> logger,
            AppDbContext context,
            IOptions<JwtSettings> jwtSettings)
        {
            _logger = logger;
            _context = context;
            _jwtSettings = jwtSettings.Value;
        }

        public async Task<AuthResult> RegisterAsync(RegisterRequest request)
        {
            try
            {
                // Validate unique email
                if (await _context.Users.AnyAsync(u => u.Email == request.Email))
                {
                    return new AuthResult { Success = false, Message = "Email already exists" };
                }

                // Hash password
                var hashedPassword = BCrypt.Net.BCrypt.HashPassword(request.Password);

                // Create user
                User user = new User
                {
                    FirstName = request.FirstName,
                    LastName = request.LastName,
                    Gender = request.Gender,
                    Email = request.Email,
                    UserID = request.UserID,
                    Username = request.Username,
                    Password = hashedPassword,
                    Token = request.Token,
                    CreatedAt = DateTime.UtcNow
                };

                await _context.Users.AddAsync(user);
                await _context.SaveChangesAsync();

                // Generate tokens
                var jwtToken = GenerateJwtToken(user);
                var refreshToken = GenerateRefreshToken(user);

                await _context.RefreshTokens.AddAsync(refreshToken);
                await _context.SaveChangesAsync();

                return new AuthResult
                {
                    Success = true,
                    Token = jwtToken,
                    RefreshToken = refreshToken.Token,
                    Message = "User registered successfully"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Registration failed for {Email}", request.Email);
                return new AuthResult { Success = false, Message = "Registration failed" };
            }
        }

        public async Task<AuthResult> LoginAsync(LoginRequest request)
        {
            try
            {
                // Find user
                var user = await _context.User
                    .FirstOrDefaultAsync(u => u.Email == request.Email);

                if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
                {
                    return new AuthResult { Success = false, Message = "Invalid credentials" };
                }

                // Generate tokens
                var jwtToken = GenerateJwtToken(user);
                var refreshToken = GenerateRefreshToken(user);

                await _context.RefreshTokens.AddAsync(refreshToken);
                await _context.SaveChangesAsync();

                return new AuthResult
                {
                    Success = true,
                    Token = jwtToken,
                    RefreshToken = refreshToken.Token,
                    Message = "Login successful"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login failed for {Email}", request.Email);
                return new AuthResult { Success = false, Message = "Login failed" };
            }
        }

        public async Task<AuthResult> RefreshTokenAsync(RefreshTokenRequest request)
        {
            try
            {
                var principal = GetPrincipalFromExpiredToken(request.Token);
                var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);

                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    return new AuthResult { Success = false, Message = "Invalid token" };
                }

                var refreshToken = await _context.RefreshTokens
                    .FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken &&
                                             rt.UserId == userId &&
                                             rt.Expires > DateTime.UtcNow &&
                                             !rt.IsUsed);

                if (refreshToken == null)
                {
                    return new AuthResult { Success = false, Message = "Invalid refresh token" };
                }

                // Mark refresh token as used
                refreshToken.IsUsed = true;
                _context.RefreshTokens.Update(refreshToken);

                // Generate new tokens
                var newJwtToken = GenerateJwtToken(user);
                var newRefreshToken = GenerateRefreshToken(user);

                await _context.RefreshTokens.AddAsync(newRefreshToken);
                await _context.SaveChangesAsync();

                return new AuthResult
                {
                    Success = true,
                    Token = newJwtToken,
                    RefreshToken = newRefreshToken.Token,
                    Message = "Token refreshed successfully"
                };
            }
            catch (SecurityTokenException ex)
            {
                _logger.LogError(ex, "Invalid JWT token");
                return new AuthResult { Success = false, Message = "Invalid token" };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token refresh failed");
                return new AuthResult { Success = false, Message = "Token refresh failed" };
            }
        }

        private string GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.UserID.ToString()),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.TokenExpirationMinutes),
                Issuer = _jwtSettings.Issuer,
                Audience = _jwtSettings.Audience,
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private RefreshToken GenerateRefreshToken(User user)
        {
            return new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays),
                UserId = user.UserID,
                Created = DateTime.UtcNow
            };
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidAudience = _jwtSettings.Audience,
                ValidateIssuer = true,
                ValidIssuer = _jwtSettings.Issuer,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.Secret)),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }

        public Task<User?> GetUserByIdAsync(string userId)
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<User>> GetAllUsersAsync()
        {
            throw new NotImplementedException();
        }

        public Task<bool> UpdateUserAsync(User user)
        {
            throw new NotImplementedException();
        }

        public Task<bool> DeleteUserAsync(string userId)
        {
            throw new NotImplementedException();
        }

        public Task RefreshTokenAsync(Controllers.RefreshTokenRequest request)
        {
            throw new NotImplementedException();
        }

        Task IUserService.RegisterAsync(RegisterRequest request)
        {
            throw new NotImplementedException();
        }

        Task IUserService.LoginAsync(LoginRequest request)
        {
            throw new NotImplementedException();
        }
    }
}
