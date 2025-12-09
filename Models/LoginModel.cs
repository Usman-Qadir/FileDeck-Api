using Microsoft.EntityFrameworkCore.Storage.ValueConversion.Internal;

namespace FileDeckApi.Models
{
    public class LoginModel
    {
        public String Email { get; set; } = string.Empty;
        public String Password { get; set; } = string.Empty;
        public bool RememberMe { get; set; } = false;
    }
}
