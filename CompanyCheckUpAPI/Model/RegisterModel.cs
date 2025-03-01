namespace CompanyCheckUpAPI.Model
{
    public class RegisterModel
    {
        public required string UserID { get; set; }
        public required string Username { get; set; }
        public required string FirstName { get; set; }
        public required string LastName { get; set; }
        public required string Email { get; set; }
        public required string Password { get; set; }
        public required string Gender { get; set; }
        public required string Role { get; set; }
        public required DateTime dateTime { get; set; }
    }
}
