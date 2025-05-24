using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTAutentication.Entities;
using JWTAutentication.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWTAutentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController(IConfiguration configuration) : ControllerBase
    {
        // Create a static user
        public static User user = new User();
        
        // Add route for post at api/authentication/register
        [HttpPost("register")]
        // Register returns a User object and takes in DTO
        public ActionResult<User> Register(UserDTO request)
        {
            var hashedPassword = new PasswordHasher<User>()
                .HashPassword(user, request.Password);
            
            user.Username = request.Username;
            user.PasswordHash = hashedPassword;

            return Ok(user);
        }

        [HttpPost("login")]
        // Login returns a json web token and takes in a DTO which contains the username and password
        public ActionResult<string> Login(UserDTO request)
        {
            if (user.Username != request.Username)
            {
                return BadRequest("User not found.");
            }

            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password)
                == PasswordVerificationResult.Failed)
            {
                return BadRequest("Incorrect password.");
            }

            string token = CreateToken(user);
            return Ok(token);
        }

        // Create JSON Web Token
        private string CreateToken(User user)
        {
            // Username, role, id, etc.
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
            };

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")));
            
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration.GetValue<string>("AppSettings:Issuer"),
                audience: configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds
            );
            
            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }
    }
}