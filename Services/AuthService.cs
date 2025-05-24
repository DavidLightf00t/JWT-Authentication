using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTAutentication.Data;
using JWTAutentication.Entities;
using JWTAutentication.Models;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthentication.Services
{
    public class AuthService(UserDbContext context, IConfiguration configuration) : IAuthService
    {
        public async Task<User?> RegisterAsync(UserDTO request)
        {
            if (await context.Users.AnyAsync(user => user.Username == request.Username))
            {
                return null;
            }

            var user = new User();
            var hashedPassword = new PasswordHasher<User>()
                .HashPassword(user, request.Password);
            
            user.Username = request.Username;
            user.PasswordHash = hashedPassword;

            // Begins tracking the user info
            context.Users.Add(user);
            // Adds user info to the database
            await context.SaveChangesAsync();

            return user;
        }

        public async Task<string?> LoginAsync(UserDTO request)
        {
            var user = await context.Users.FirstOrDefaultAsync(user => user.Username == request.Username);
            if (user == null)
            {
                return null;
            }
            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password)
                == PasswordVerificationResult.Failed)
            {
                return null;
            }

            return CreateToken(user);
        }
        
        // Create JSON Web Token
        private string CreateToken(User user)
        {
            // Username, role, id, etc.
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
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