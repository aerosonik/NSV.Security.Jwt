using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace NSV.Security.JWT
{
    internal class JwtService : IJwtService
    {
        private readonly JwtOptions _options;

        internal JwtService(JwtOptions options)
        {
            _options = options;
        }

        public JwtTokenResult IssueAccessToken(
            string id,
            string name,
            IEnumerable<string> roles)
        {
            return IssueAccessToken(id, name, roles, null);
        }

        public JwtTokenResult IssueAccessToken(
            string id,
            string name,
            IEnumerable<string> roles,
            IEnumerable<KeyValuePair<string, string>> customClaims)
        {
            var accessResult = GetAccessToken(id, name, roles, customClaims);
            var refreshResult = GetRefreshToken(id, name);
            var model = new TokenModel(
                (accessResult.token, accessResult.expiry, accessResult.jti),
                (refreshResult.token, refreshResult.expiry, refreshResult.jti)
            );
            return JwtTokenResult.Ok(model, id, accessResult.accessClaims);
        }

        public JwtTokenResult RefreshAccessToken(
            string accessToken,
            string refreshToken)
        {
            return RefreshAccessToken(accessToken, refreshToken, null);
        }

        public JwtTokenResult RefreshAccessToken(
            string accessToken,
            string refreshToken,
            IEnumerable<string> customClaimsType)
        {
            var result = ValidateRefreshToken(refreshToken);
            if (result.result != JwtTokenResult.TokenResult.Ok)
                return new JwtTokenResult(result.result);

            Claim[] accessClaims = null;
            try
            {
                accessClaims = new JwtSecurityTokenHandler()
                    .ReadJwtToken(accessToken)
                    .Claims.ToArray();
            }
            catch
            {
                return JwtTokenResult.AccessInvalid();
            }

            var identityOptions = new IdentityOptions();
            var refreshId = result.claims
                .FirstOrDefault(x => x.Type
                .Equals(JwtRegisteredClaimNames.Sub))
                .Value;

            var accessId = accessClaims
                .FirstOrDefault(x => x.Type
                .Equals(JwtRegisteredClaimNames.Sub))
                .Value;
            if (!refreshId.Equals(accessId))
                return JwtTokenResult.Mismatch();

            var refreshJti = result.claims
                .FirstOrDefault(x => x.Type
                .Equals(JwtRegisteredClaimNames.Jti))
                .Value;
            var accessName = accessClaims
                .FirstOrDefault(x => x.Type
                .Equals(identityOptions.ClaimsIdentity.UserNameClaimType))
                .Value;
            var roles = accessClaims
                .Where(x => x.Type
                .Equals(ClaimTypes.Role));

            List<Claim> claims = null;
            if (customClaimsType != null)
            {
                var customClaims = accessClaims
                    .Where(claim => customClaimsType.Contains(claim.Type))
                    .ToArray();
                if(customClaims != null && customClaims.Length >0)
                    claims = GetAccessClaims(accessId, accessName, roles, customClaims);
                else
                    claims = GetAccessClaims(accessId, accessName, roles);
            }
            else
            {
                claims = GetAccessClaims(accessId, accessName, roles);
            }

            var newAccessToken = CreateAccessToken(claims);

            if (result.update)
            {
                var newRefreshToken = GetRefreshToken(accessId, accessName);

                return JwtTokenResult.Ok(new TokenModel
                (
                    newAccessToken,
                    newRefreshToken
                ),
                accessId,
                accessClaims);
            }

            return JwtTokenResult.Ok(
                new TokenModel(newAccessToken, (null, default, refreshJti)),
                accessId,
                accessClaims);
        }

        public TokenDetails GetTokenDetails(string token)
        {
            var jwtToken = new JwtSecurityTokenHandler()
                    .ReadJwtToken(token);
            var claims = jwtToken.Claims.ToArray();
            var expiration = jwtToken.ValidTo;
            return new TokenDetails(expiration, claims);
        }

        #region private methods
        private (string token, DateTime expiry, string jti) GetRefreshToken(
            string id,
            string name)
        {
            var claims = GetRefreshClaims(id, name);
            var jti = claims
                .FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)
                .Value;
            var (token, expiry) = CreateRefreshToken(claims);
            return (token, expiry, jti);
        }

        private (string token, DateTime expiry, string jti, IEnumerable<Claim> accessClaims) 
            GetAccessToken(
            string id,
            string name,
            IEnumerable<string> roles,
            IEnumerable<KeyValuePair<string, string>> customClaims = null)
        {
            var claims = GetAccessClaims(id, name, roles, customClaims);
            var (token, expiry, jti) = CreateAccessToken(claims);
            return (token, expiry, jti, claims);
        }

        private (string token, DateTime expiry, string jti) CreateAccessToken(
            IEnumerable<Claim> claims)
        {
            var expiry = DateTime.UtcNow.Add(_options.AccessTokenExpiry);
            var jwt = new JwtSecurityToken(
                issuer: _options.ValidIssuer,
                audience: _options.ValidAudience,
                notBefore: DateTime.UtcNow,
                claims: claims,
                expires: expiry,
                signingCredentials: new SigningCredentials(
                    new SymmetricSecurityKey(_options.AccessSecurityKeyBytes),
                    SecurityAlgorithms.HmacSha256));
            var token = new JwtSecurityTokenHandler().WriteToken(jwt);
            var jti = claims
                .FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)
                .Value;
            return (token, expiry, jti);
        }

        private (string token, DateTime expiry) CreateRefreshToken(
            IEnumerable<Claim> claims)
        {
            var expiry = DateTime.UtcNow.Add(_options.RefreshTokenExpiry);
            var jwt = new JwtSecurityToken(
                issuer: _options.ValidIssuer,
                audience: _options.ValidAudience,
                notBefore: DateTime.UtcNow,
                claims: claims,
                expires: expiry,
                signingCredentials: new SigningCredentials(
                    new SymmetricSecurityKey(_options.RefreshSecurityKeyBytes),
                    SecurityAlgorithms.HmacSha256));
            var token = new JwtSecurityTokenHandler().WriteToken(jwt);
            return (token, expiry);
        }

        private List<Claim> GetAccessClaims(
            string id,
            string name,
            IEnumerable<string> roles,
            IEnumerable<KeyValuePair<string, string>> customClaims = null)
        {
            var identityOptions = new IdentityOptions();
            var claims = GetRefreshClaims(id, name);

            claims.AddRange(roles.Select(role =>
                new Claim(ClaimTypes.Role, role)));
            if (customClaims != null)
                claims.AddRange(customClaims.Select(x =>
                    new Claim(x.Key, x.Value)));
            return claims;
        }

        private List<Claim> GetAccessClaims(
            string id,
            string name,
            IEnumerable<Claim> roles,
            IEnumerable<Claim> customClaims = null)
        {
            var claims = GetRefreshClaims(id, name);

            claims.AddRange(roles);
            if (customClaims != null)
                claims.AddRange(customClaims);
            return claims;
        }

        private List<Claim> GetRefreshClaims(
            string id,
            string name)
        {
            if (string.IsNullOrWhiteSpace(id))
                id = string.Empty;
            if (string.IsNullOrWhiteSpace(name))
                name = string.Empty;
            var identityOptions = new IdentityOptions();
            var claims = new List<Claim>
            {
                //new Claim(JwtRegisteredClaimNames.Sub, name),
                new Claim(JwtRegisteredClaimNames.Sub, id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString(),
                    ClaimValueTypes.Integer64),
                //new Claim(identityOptions.ClaimsIdentity.UserIdClaimType, id),
                new Claim(identityOptions.ClaimsIdentity.UserNameClaimType, name)
            };

            return claims;
        }

        private (JwtTokenResult.TokenResult result, bool update, Claim[] claims)
            ValidateRefreshToken(string refreshToken)
        {
            var jwt = new JwtSecurityTokenHandler();
            var parameters = GetRefreshTokenValidationParameters();

            SecurityToken validatedToken;
            try
            {
                jwt.ValidateToken(
                    refreshToken,
                    parameters,
                    out validatedToken);
            }
            catch (Exception)
            {
                return (JwtTokenResult.TokenResult.RefreshTokenInvalid, false, null);
            }

            if (!(validatedToken is JwtSecurityToken jwtSecurityToken) ||
                !jwtSecurityToken.Header.Alg
                    .Equals(
                        SecurityAlgorithms.HmacSha256,
                        StringComparison.InvariantCultureIgnoreCase))
            {
                return (JwtTokenResult.TokenResult.RefreshTokenInvalid, false, null);
            }

            var claims = jwtSecurityToken.Claims.ToArray();
            if (DateTime.UtcNow < jwtSecurityToken.ValidTo)
            {
                var updatePeriod = jwtSecurityToken.ValidTo
                    .Subtract(_options.UpdateRefreshTokenBeforeExpired);
                if (DateTime.UtcNow >= updatePeriod)
                    return (JwtTokenResult.TokenResult.Ok, true, claims);
                return (JwtTokenResult.TokenResult.Ok, false, claims);
            }
            return (JwtTokenResult.TokenResult.RefreshTokenExpired, false, claims);
        }

        private TokenValidationParameters GetRefreshTokenValidationParameters()
        {
            return new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _options.ValidIssuer,
                ValidAudience = _options.ValidAudience,
                IssuerSigningKey = new SymmetricSecurityKey(
                    _options.RefreshSecurityKeyBytes)
            };
        }
        #endregion
    }
}
