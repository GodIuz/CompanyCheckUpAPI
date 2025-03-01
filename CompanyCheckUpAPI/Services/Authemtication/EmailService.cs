using MimeKit;
using MailKit.Net.Smtp;
using MailKit.Security;
 
namespace CompanyCheckUpAPI.Services.Authemtication
{
    public class EmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration config)
        {
            _config = config;
        }

        public async Task SendPasswordResetEmailAsync(string email, string resetLink)
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(
                _config["Email:DisplayName"],
                _config["Email:From"]
            ));
            message.To.Add(MailboxAddress.Parse(email));
            message.Subject = "Password Reset";
            message.Body = new TextPart("plain")
            {
                Text = $"Reset your password here: {resetLink}"
            };

            using var client = new SmtpClient();
            await client.ConnectAsync(
                _config["Email:Host"],
                _config.GetValue<int>("Email:Port"),
                SecureSocketOptions.StartTls
            );
            await client.AuthenticateAsync(
                _config["Email:Username"],
                _config["Email:Password"]
            );
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        }
    }
}
