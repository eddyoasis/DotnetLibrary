using ClassLibrary1.Models;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Threading.Tasks;

namespace ClassLibrary1.Services
{
    public interface IAuthService
    {
        Task<string> Login(LDAPAppSetting ldapAppSetting, JwtModel jwtModel, string username, string password);
    }

    public class AuthService : IAuthService
    {
        public async Task<string> Login(LDAPAppSetting ldapAppSetting, JwtModel jwtModel, string username, string password)
        {
            var token = string.Empty;

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

                SearchResult result = searcher.FindOne();
                string fullName = result?.Properties["displayName"]?[0]?.ToString();

                IJwtTokenService jwtTokenService = new JwtTokenService();

                token = jwtTokenService.GenerateJwtToken(jwtModel, fullName);

                return token;
            }
            catch (LdapException ex)
            {
                return token;
            }
        }
    }
}
