using CompanyCheckUpAPI.Model;

namespace CompanyCheckUpAPI.Services.Authemtication
{
    public class RefreshToken
    {
        public string Token { get; set; } = string.Empty;
        public DateTime Created { get; set; }
        public DateTime Expires { get; set; }
        public bool IsUsed { get; set; }
        public string UserId { get; set; } = string.Empty;
        public User Email { get; set; }
    }
}
