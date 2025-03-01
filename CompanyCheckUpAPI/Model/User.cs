using System.ComponentModel.DataAnnotations;

namespace CompanyCheckUpAPI.Model
{
    public class User
    {
        [Key]
        public required string UserID { get; set; }
        public required string Username { get; set; }
        public required string FirstName { get; set; }
        public required string LastName { get; set; }
        public required string Email { get; set; }
        public required string Password { get; set; }
        public string Gender { get; set; }
        public string Role { get; set; }
        public DateTime DOB { get; set; }
        public DateTime CreatedAt { get; set; }
        public required string Token { get; set; }
    }
}
