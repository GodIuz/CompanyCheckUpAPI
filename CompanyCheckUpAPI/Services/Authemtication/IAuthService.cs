namespace CompanyCheckUpAPI.Services.Authemtication
{
    public interface IAuthService
    {
        Task<AuthResult> RegisterAsync(string email, string password);
        Task<AuthResult> LoginAsync(string email, string password);

        // External logins
        Task<AuthResult> LoginWithFacebookAsync(string accessToken);
        Task<AuthResult> LoginWithGoogleAsync(string accessToken);

        // Password reset
        Task<AuthResult> ForgotPasswordAsync(string email);
        Task<AuthResult> ResetPasswordAsync(string email, string token, string newPassword);
    }
}
