using ClassLibrary1.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace ClassLibrary1.Helpers
{
    public static class JwtTokenHelper
    {
        public static string GenerateJwtToken(JwtAppSetting config, JwtModel jwtInfo)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Name, jwtInfo.Username),
                new Claim(JwtRegisteredClaimNames.Sub, jwtInfo.Username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, jwtInfo.Email),
                new Claim("department", jwtInfo.Department),
                new Claim("jobtitle", jwtInfo.JobTitle)
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

        public static JwtDecodeModel DecodeJwtToken(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            var result = new JwtDecodeModel
            {
                Username = jwtToken.Claims.FirstOrDefault(c => c.Type == "sub")?.Value,
                Email = jwtToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value,
                Department = jwtToken.Claims.FirstOrDefault(c => c.Type == "department")?.Value,
                JobTitle = jwtToken.Claims.FirstOrDefault(c => c.Type == "jobtitle")?.Value,
                Claims = jwtToken.Claims
            };

            return result;
        }
    }
}
