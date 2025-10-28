using ClassLibrary1.Helpers;
using ClassLibrary1.Models;

namespace ClassLibrary1.Services
{
    public interface IJwtTokenService
    {
        string GenerateJwtToken(JwtAppSetting config, JwtModel jwtInfo);
    }

    public class JwtTokenService : IJwtTokenService
    {
        public string GenerateJwtToken(JwtAppSetting config, JwtModel jwtInfo)
        {
            return JwtTokenHelper.GenerateJwtToken(config, jwtInfo);
        }
    }
}
