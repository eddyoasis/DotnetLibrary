using ClassLibrary1.Models;
using System;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace ClassLibrary1.Services
{
    public interface IAuthService
    {
        Task<JwtTokenModel> RefreshToken(JwtAppSetting jwtAppSetting, JwtModel jwtInfo);
        Task<JwtTokenModel> Login(LDAPAppSetting ldapAppSetting, JwtAppSetting jwtAppSetting, string username, string password);
        Task<JwtTokenModel> LoginByPass(JwtAppSetting jwtAppSetting, string username, string password);
    }

    public class AuthService : IAuthService
    {
        IJwtTokenService jwtTokenService = new JwtTokenService();

        public async Task<JwtTokenModel> RefreshToken(JwtAppSetting jwtAppSetting, JwtModel jwtInfo)
        {
            var jwtTokenModel = new JwtTokenModel();

            try
            {
                var accessToken = jwtTokenService.GenerateJwtToken(jwtAppSetting, jwtInfo);
                var refreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

                jwtTokenModel = new JwtTokenModel
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken
                };

                return jwtTokenModel;
            }
            catch (LdapException ex)
            {
                return jwtTokenModel;
            }
        }

        public async Task<JwtTokenModel> Login(LDAPAppSetting ldapAppSetting, JwtAppSetting jwtAppSetting, string username, string password)
        {
            var jwtTokenModel = new JwtTokenModel();

            try
            {
                var identifier = new LdapDirectoryIdentifier(ldapAppSetting.Server, ldapAppSetting.Port);
                using var connection = new LdapConnection(identifier);

                connection.SessionOptions.ProtocolVersion = 3;
                connection.SessionOptions.VerifyServerCertificate += (conn, cert) => true;

                connection.SessionOptions.SecureSocketLayer = ldapAppSetting.Port == 636;
                connection.AuthType = AuthType.Basic;

                string domainUser = $"{ldapAppSetting.Domain}\\{username}"; // NetBIOS domain\username

                var credential = new NetworkCredential(domainUser, password);

                connection.Bind(credential); // ✅ Success if no exception

                DirectoryEntry entry = new($"LDAP://{ldapAppSetting.Domain}");
                DirectorySearcher searcher = new(entry)
                {
                    Filter = $"(sAMAccountName={username})"
                };
                searcher.PropertiesToLoad.Add("displayName");
                searcher.PropertiesToLoad.Add("mail");         // Email
                searcher.PropertiesToLoad.Add("department");   // Department
                searcher.PropertiesToLoad.Add("title");        // Job Title

                SearchResult result = searcher.FindOne();

                var jwtInfo = new JwtModel
                {
                    Username = result?.Properties["displayName"]?[0]?.ToString(),
                    Email = result?.Properties["mail"]?[0]?.ToString(),
                    Department = result?.Properties["department"]?[0]?.ToString(),
                    JobTitle = result?.Properties["title"]?[0]?.ToString()
                };

                var accessToken = jwtTokenService.GenerateJwtToken(jwtAppSetting, jwtInfo);
                var refreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

                jwtTokenModel = new JwtTokenModel
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken
                };

                return jwtTokenModel;
            }
            catch (LdapException ex)
            {
                return jwtTokenModel;
            }
        }

        public async Task<JwtTokenModel> LoginByPass(JwtAppSetting jwtAppSetting, string username, string password)
        {
            var jwtTokenModel = new JwtTokenModel();

            var jwtInfo = new JwtModel
            {
                Username = username,
                Email = $"{username}@mail.com",
                Department = "Information Technology",
                JobTitle = "Guest"
            };

            try
            {
                var accessToken = jwtTokenService.GenerateJwtToken(jwtAppSetting, jwtInfo);
                var refreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

                jwtTokenModel = new JwtTokenModel
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken
                };

                return jwtTokenModel;
            }
            catch (LdapException ex)
            {
                return jwtTokenModel;
            }
        }
    }
}
