using FileDeckApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace FileDeckApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        // POST: api/auth/register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
                return Conflict(new { Message = "User with this email already exists" });

            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                DisplayName = model.DisplayName,
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            // optionally assign default role
            if (!await _roleManager.RoleExistsAsync("User"))
                await _roleManager.CreateAsync(new IdentityRole("User"));

            await _userManager.AddToRoleAsync(user, "User");

            return Ok(new { Message = "User registered successfully" });
        }

        // POST: api/auth/login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized(new { Message = "Invalid credentials" });

            // Update last login
            user.LastLoginAt = DateTime.UtcNow;

            // Generate refresh token
            var refreshToken = GenerateRefreshToken();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(Convert.ToDouble(
                _configuration.GetSection("JwtSettings")["RefreshTokenExpirationDays"] ?? "7"));

            await _userManager.UpdateAsync(user);

            // Roles for this user
            var roles = await _userManager.GetRolesAsync(user);

            // Generate JWT
            var token = GenerateJwtToken(user, roles);

            return Ok(new TokenResponse
            {
                Token = token,
                RefreshToken = refreshToken,
                Expiration = DateTime.UtcNow.AddMinutes(Convert.ToDouble(
                    _configuration.GetSection("JwtSettings")["ExpirationMinutes"] ?? "60")),
                User = new UserInfo
                {
                    Id = user.Id,
                    Email = user.Email ?? "",
                    DisplayName = user.DisplayName,
                    Roles = roles.ToList()
                }
            });
        }

        // POST: api/auth/refresh
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenModel model)
        {
            if (string.IsNullOrEmpty(model.Token) || string.IsNullOrEmpty(model.RefreshToken))
                return BadRequest(new { Message = "Token and refresh token are required" });

            try
            {
                var principal = GetPrincipalFromExpiredToken(model.Token);
                if (principal == null)
                    return BadRequest(new { Message = "Invalid or malformed token" });

                var username = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                             ?? principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

                if (string.IsNullOrEmpty(username))
                    return BadRequest(new { Message = "Invalid token: no user identifier found" });

                var user = await _userManager.FindByNameAsync(username);
                if (user == null)
                    return BadRequest(new { Message = "User not found" });

                if (user.RefreshToken != model.RefreshToken)
                    return BadRequest(new { Message = "Invalid refresh token: token mismatch" });

                if (user.RefreshTokenExpiry <= DateTime.UtcNow)
                    return BadRequest(new { Message = "Refresh token expired" });

                // Generate new tokens
                var roles = await _userManager.GetRolesAsync(user);
                var newJwtToken = GenerateJwtToken(user, roles);
                var newRefreshToken = GenerateRefreshToken();

                // Update refresh token
                user.RefreshToken = newRefreshToken;
                user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(Convert.ToDouble(
                    _configuration.GetSection("JwtSettings")["RefreshTokenExpirationDays"] ?? "7"));

                await _userManager.UpdateAsync(user);

                return Ok(new TokenResponse
                {
                    Token = newJwtToken,
                    RefreshToken = newRefreshToken,
                    Expiration = DateTime.UtcNow.AddMinutes(Convert.ToDouble(
                        _configuration.GetSection("JwtSettings")["ExpirationMinutes"] ?? "60")),
                    User = new UserInfo
                    {
                        Id = user.Id,
                        Email = user.Email ?? "",
                        DisplayName = user.DisplayName,
                        Roles = roles.ToList()
                    }
                });
            }
            catch (SecurityTokenException ex)
            {
                return BadRequest(new { Message = $"Token validation failed: {ex.Message}" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Message = $"Internal server error: {ex.Message}" });
            }
        }

        // POST: api/auth/revoke
        [HttpPost("revoke")]
        [Authorize] // ensure only authenticated users can call this
        public async Task<IActionResult> Revoke()
        {
            var username = User.Identity?.Name;
            if (string.IsNullOrEmpty(username))
                return BadRequest(new { Message = "Invalid user" });

            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
                return BadRequest(new { Message = "User not found" });

            if (string.IsNullOrEmpty(user.RefreshToken))
                return BadRequest(new { Message = "No active refresh token to revoke" });

            user.RefreshToken = null;
            user.RefreshTokenExpiry = null;
            await _userManager.UpdateAsync(user);

            return Ok(new { Message = "Logged Out Successfully" });
        }

        private string GenerateJwtToken(ApplicationUser user, IList<string> roles)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var key = Encoding.UTF8.GetBytes(jwtSettings["Key"] ?? throw new InvalidOperationException("JWT Key is not configured"));
            var creds = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName ?? user.Email ?? ""),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? ""),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("DisplayName", user.DisplayName ?? "")
            };

            // add role claims
            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(jwtSettings["ExpirationMinutes"] ?? "60")),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var key = Encoding.UTF8.GetBytes(jwtSettings["Key"] ?? throw new InvalidOperationException("JWT Key is not configured"));

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false, // we want to get the principal even if token is expired
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtSettings["Issuer"],
                ValidAudience = jwtSettings["Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ClockSkew = TimeSpan.Zero // remove clock skew for more precise validation
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            try
            {
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

                // Additional validation for JWT token type and algorithm
                if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                    !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    return null;
                }

                return principal;
            }
            catch (SecurityTokenExpiredException)
            {
                // This is expected for expired tokens - we're using ValidateLifetime = false
                return null;
            }
            catch (SecurityTokenInvalidSignatureException)
            {
                return null;
            }
            catch (SecurityTokenMalformedException)
            {
                return null;
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}