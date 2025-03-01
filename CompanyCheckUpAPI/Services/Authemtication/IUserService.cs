using CompanyCheckUpAPI.Controllers;
using CompanyCheckUpAPI.Model;
using Google.Apis.Auth.OAuth2.Requests;
using RefreshTokenRequest = CompanyCheckUpAPI.Controllers.RefreshTokenRequest;

namespace CompanyCheckUpAPI.Services.Authemtication
{
    public interface IUserService
    {
        Task<User?> GetUserByIdAsync(string userId);
        Task<IEnumerable<User>> GetAllUsersAsync();
        Task<bool> UpdateUserAsync(User user);
        Task<bool> DeleteUserAsync(string userId);
        Task RefreshTokenAsync(RefreshTokenRequest request);
        Task RegisterAsync(RegisterRequest request);
        Task LoginAsync(LoginRequest request);
    }
}
