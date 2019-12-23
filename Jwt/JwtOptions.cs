using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;

namespace NSV.Security.JWT
{
    public class JwtOptions
    {
        public string ValidIssuer { get; set; } = "identity.nsv.pub";
        public string ValidAudience { get; set; } = "identity.nsv.pub";
        public string AccessSecurityKey { get; set; } = "c12477f1-c84e-4a82-aa4d-7574ee08e592@identity.nsv.pub/defaultAcessSecurityKey";
        public TimeSpan AccessTokenExpiry { get; set; } = TimeSpan.FromMinutes(30);
        public string RefreshSecurityKey { get; set; } = "c16455f1-c88e-4b92-bb4d-79749e989592@identity.nsv.pub/defaultRefreshSecurityKey";
        public TimeSpan RefreshTokenExpiry { get; set; } = TimeSpan.FromDays(5);
        public TimeSpan UpdateRefreshTokenBeforeExpired { get; set; } = TimeSpan.FromDays(1);

        public byte[] AccessSecurityKeyBytes
        {
            get
            {
                if (_accessSecurityKeyBytes == null)
                    _accessSecurityKeyBytes = Encoding
                        .UTF8.GetBytes(AccessSecurityKey);

                return _accessSecurityKeyBytes;
            }
        }
        private byte[] _accessSecurityKeyBytes;

        public byte[] RefreshSecurityKeyBytes
        {
            get
            {
                if (_refreshSecurityKeyBytes == null)
                    _refreshSecurityKeyBytes = Encoding
                        .UTF8.GetBytes(RefreshSecurityKey);

                return _refreshSecurityKeyBytes;
            }
        }
        private byte[] _refreshSecurityKeyBytes;

        public TokenValidationParameters GetAccessTokenValidationParameters()
        {
            return new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = ValidIssuer,
                ValidAudience = ValidAudience,
                IssuerSigningKey = new SymmetricSecurityKey(AccessSecurityKeyBytes)
            };
        }
    }
}
