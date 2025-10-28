using System.Collections.Generic;
using System.Security.Claims;

namespace ClassLibrary1.Models
{
    public class JwtAppSetting
    {
        public string Key { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
    }

    public class JwtModel
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Department { get; set; }
        public string JobTitle { get; set; }
    }

    public class JwtTokenModel
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }

    public class JwtDecodeModel : JwtModel
    {
        public IEnumerable<Claim> Claims  { get; set; }
    }
}
