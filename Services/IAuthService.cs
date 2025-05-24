using JWTAutentication.Entities;
using JWTAutentication.Models;

namespace JWTAuthentication.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(UserDTO request);
        Task<string?> LoginAsync(UserDTO request);
    }
}