namespace CompanyCheckUpAPI.Services.Authemtication
{
    public class AuthResult
    {

        public bool Success { get; set; }
        public string Token { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public string RefreshToken {  set; get; } = string.Empty;
        public IEnumerable<string> Errors { get; set; } = new List<string>();
    }
}
