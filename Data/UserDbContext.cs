using JWTAuthentication.Entities;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthentication.Data
{
    public class UserDbContext(DbContextOptions<UserDbContext> options) : DbContext(options)
    {
        // Creates a Users table in database
        public DbSet<User> Users { get; set; }
    }
}