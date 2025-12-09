using Microsoft.AspNetCore.Identity;



namespace FileDeckApi.Models
{
    public class ApplicationUser : IdentityUser
    {
        // Extra profile info
        public string DisplayName { get; set; } = string.Empty;

        // Audit info
        public DateTime CreatedAt { get; set; } 
        public DateTime LastLoginAt { get; set; }

        // Account status
        public bool IsActive { get; set; } = true;

        // refresh token support
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiry { get; set; }
    }
}

