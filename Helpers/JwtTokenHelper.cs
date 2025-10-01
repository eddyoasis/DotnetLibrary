using ClassLibrary1.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace ClassLibrary1.Helpers
{
    public class JwtTokenHelper
    {
        public static string GenerateJwtToken(JwtModel config, string username)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: config.Issuer,
                audience: config.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public static string DecodeJwtToken(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            // Extract username or other claims
            var usernameClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;

            return usernameClaim ?? "Unknown User";
        }
    }
}
