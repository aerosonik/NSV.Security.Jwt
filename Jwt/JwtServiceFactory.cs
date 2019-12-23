using System;
using System.Collections.Generic;
using System.Text;

namespace NSV.Security.JWT
{
    public class JwtServiceFactory
    {
        public static IJwtService Create(
            TimeSpan accessTokenExpiry,
            TimeSpan refreshTokenExpiry,
            TimeSpan updateRefreshTokenBeforeExpired)
        {
            var options = new JwtOptions
            {
                AccessTokenExpiry = accessTokenExpiry,
                RefreshTokenExpiry = refreshTokenExpiry,
                UpdateRefreshTokenBeforeExpired = updateRefreshTokenBeforeExpired
            };
            return new JwtService(options);
        }
    }
}
