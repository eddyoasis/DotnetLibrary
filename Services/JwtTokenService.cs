using ClassLibrary1.Helpers;
using ClassLibrary1.Models;

namespace ClassLibrary1.Services
{
    public interface IJwtTokenService
    {
        string GenerateJwtToken(JwtModel config, string username);
    }

    public class JwtTokenService : IJwtTokenService
    {
        public string GenerateJwtToken(JwtModel config, string username)
        {
            return JwtTokenHelper.GenerateJwtToken(config, username);
        }
    }
}
