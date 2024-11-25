using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Endpoint.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        [AllowAnonymous]
        [HttpPost("auth/login")]
        public async Task<IActionResult> Login()
        {
            // Example claims
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "admin"),
                new Claim("UserId", "12345"), // Custom claim
            };

            var identity = new ClaimsIdentity(claims, "CookieAuth");
            var principal = new ClaimsPrincipal(identity);

            // Sign in the user and issue the cookie
            await HttpContext.SignInAsync("CookieAuth", principal);

            return Ok(new { Message = "Cookie generated successfully!" });
        }
        
        [AllowAnonymous]
        [HttpGet("/user")]
        public async Task<IActionResult> GetUserAsync()
        {
            await Task.CompletedTask;
            return Ok(new { UserName = "admin", Email = "admin@admin.com" });
        }

        [Authorize(Policy = "CookieOnly")]
        [HttpGet("/user/{id:int}")]
        public async Task<IActionResult> GetUserByIdAsync(int id)
        {
            await Task.CompletedTask;
            return Ok(new { id, UserName = "admin", Email = "admin@admin.com" });
        }

        [Authorize(AuthenticationSchemes = "SessionId")]
        [HttpGet("/user/{name}")]
        public async Task<IActionResult> GetUserByNameAsync(string name)
        {
            await Task.CompletedTask;
            return Ok(new { name, UserName = "admin", Email = "admin@admin.com" });
        }

        [HttpPost("/user/{name}")]
        public async Task<IActionResult> UpdateUserByNameAsync(string name)
        {
            await Task.CompletedTask;
            return Ok(new { name, status = "Updated" });
        }
    }
}