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
        /// <summary>
        /// Test login method which creates cookie in the response
        /// </summary>
        /// <returns></returns>
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
        
        /// <summary>
        /// Test Anonymous attribute
        /// </summary>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpGet("/user")]
        public async Task<IActionResult> GetUserAsync()
        {
            await Task.CompletedTask;
            return Ok(new { UserName = "admin", Email = "admin@admin.com" });
        }
        
        /// <summary>
        /// Test CookieOnly access
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [Authorize(Policy = "CookieOnly")]
        [HttpGet("/user/{id:int}")]
        public async Task<IActionResult> GetUserByIdAsync(int id)
        {
            await Task.CompletedTask;
            return Ok(new { id, UserName = "admin", Email = "admin@admin.com" });
        }

        /// <summary>
        /// Test session id authorization
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        [Authorize(AuthenticationSchemes = "SessionId")]
        [HttpGet("/user/{name}")]
        public async Task<IActionResult> GetUserByNameAsync(string name)
        {
            await Task.CompletedTask;
            return Ok(new { name, UserName = "admin", Email = "admin@admin.com" });
        }

        /// <summary>
        /// Test global authorize if functioning as expected.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        [HttpPost("/user/{name}")]
        public async Task<IActionResult> UpdateUserByNameAsync(string name)
        {
            await Task.CompletedTask;
            return Ok(new { name, status = "Updated" });
        }
    }
}