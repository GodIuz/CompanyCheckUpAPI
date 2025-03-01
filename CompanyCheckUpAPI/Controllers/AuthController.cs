using Microsoft.AspNetCore.Mvc;
using CompanyCheckUpAPI.Services.Authemtication;
using Microsoft.Extensions.Logging;

namespace CompanyCheckUpAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly ILogger<AuthController> _logger;
        public AuthController(IUserService userService, ILogger<AuthController> logger)
        {
            _userService = userService;
            _logger = logger;
        }


        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest("Invalid request data.");

            var result = await _userService.RegisterAsync(request);
            if (!result.Success)
            {
                _logger.LogWarning("User registration failed: {Message}", result.Message);
                return BadRequest(result.Message);
            }
            return Ok(result);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest("Invalid request data.");

            var result = await _userService.LoginAsync(request);
            if (!result.Success)
            {
                _logger.LogWarning("Login attempt failed for user: {Username}", request.Username);
                return Unauthorized(result.Message);
            }
            return Ok(result);
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            var result = await _userService.RefreshTokenAsync(request);
            if (!result.Success)
            {
                return BadRequest(result.Message);
            }
            return Ok(result);
        }
    }
}
