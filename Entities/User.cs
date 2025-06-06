namespace JWTAuthentication.Entities
{
    // User object
    public class User
    {
        public Guid Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        // C
        public string Role { get; set; } = string.Empty;
    }
}