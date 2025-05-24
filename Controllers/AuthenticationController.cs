using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTAutentication.Entities;
using JWTAutentication.Models;
using JWTAuthentication.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController(IAuthService authService) : ControllerBase
    {
        // Add route for post at api/authentication/register
        [HttpPost("register")]
        // Register returns a User object and takes in DTO
        public async Task<ActionResult<User>> Register(UserDTO request)
        {
            var user = await authService.RegisterAsync(request);
            if (user is null)
            {
                return BadRequest("Username already exists.");
            }

            return Ok(user);
        }

        [HttpPost("login")]
        // Login returns a json web token and takes in a DTO which contains the username and password
        public async Task<ActionResult<string>> Login(UserDTO request)
        {
            var token = await authService.LoginAsync(request);
            if (token is null)
            {
                return BadRequest("Username or password is incorrect.");
            }
            return Ok(token);
        }
        
        [Authorize]
        [HttpGet]
        public IActionResult AuthenticatedOnlyEndpoint()
        {
            return Ok("You are authenticated.");
        }
    }
}