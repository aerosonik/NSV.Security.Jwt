using System;

namespace NSV.Security.JWT
{
    public class JwtServiceFactory
    {
        public static IJwtService Create(
            TimeSpan accessTokenExpiry,
            TimeSpan refreshTokenExpiry,
            TimeSpan longTermRefreshTokenExpiry,
            string longTermRefreshTokenClaim,
            TimeSpan updateRefreshTokenBeforeExpired)
        {
            var options = new JwtOptions
            {
                AccessTokenExpiry = accessTokenExpiry,
                RefreshTokenExpiry = refreshTokenExpiry,
                LongTermRefreshTokenExpiry = longTermRefreshTokenExpiry,
                UpdateRefreshTokenBeforeExpired = updateRefreshTokenBeforeExpired,
                LongTermRefreshTokenClaim = longTermRefreshTokenClaim
            };
            return new JwtService(options);
        }

        public static IJwtService Create(
            TimeSpan accessTokenExpiry,
            TimeSpan refreshTokenExpiry,
            TimeSpan updateRefreshTokenBeforeExpired)
        {
            var options = new JwtOptions
            {
                AccessTokenExpiry = accessTokenExpiry,
                RefreshTokenExpiry = refreshTokenExpiry,
                LongTermRefreshTokenExpiry = refreshTokenExpiry,
                UpdateRefreshTokenBeforeExpired = updateRefreshTokenBeforeExpired
            };
            return new JwtService(options);
        }
    }
}
