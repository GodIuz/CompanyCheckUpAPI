
namespace CompanyCheckUpAPI.Services.Authemtication
{
    public interface IEmailService
    {
        Task SendPasswordResetEmailAsync(string email, string resetLink);
    }
}