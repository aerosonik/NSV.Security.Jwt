using Microsoft.AspNetCore.Identity;
using NSV.Security.JWT;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;
using System.IdentityModel.Tokens.Jwt;
using System.Collections.Generic;

namespace NSV.Security.Jwt.UnitTests
{
    public class JwtServiceTests
    {
        public (string id, string name, string[] roles) GetUser()
        {
            return (Guid.NewGuid().ToString(),
                "User1",
                new[] { "user", "trainer" });
        }

        public (string id, string name, string[] roles, IEnumerable<KeyValuePair<string,string>> claims) GetUserWithCustomClaime()
        {
            return (Guid.NewGuid().ToString(),
                "User1",
                new[] { "user", "trainer" },
                new KeyValuePair<string, string>[] {new KeyValuePair<string, string>("deviceid", "d8fa7d6e-726f-4d52-83da-98e0b7adf2f6") });
        }

        [Fact]
        public void IssueAccessTokenWithCustomClaim()
        {
            var jwtService = JwtServiceFactory.Create(
                TimeSpan.FromSeconds(10),
                TimeSpan.FromMinutes(5),
                TimeSpan.FromSeconds(10));
            var user = GetUserWithCustomClaime();

            var access = jwtService
                .IssueAccessToken(user.id, user.name, user.roles, user.claims);

            var customClaimsType = user.claims.Select(x => x.Key).ToArray();

            Assert.True(access.Result == JwtTokenResult.TokenResult.Ok);
            Assert.NotNull(access.Tokens);
            Assert.NotNull(access.Tokens.AccessToken);
            Assert.NotNull(access.Tokens.RefreshToken);
            var testclaims = access.AccessClaims
                .Where(x => customClaimsType.Contains(x.Type))
                .Select(x => new KeyValuePair<string, string>(x.Type, x.Value))
                .ToArray();
            foreach(var claimPair in testclaims)
            {
                Assert.Contains(claimPair, user.claims);
            }
            var identityOptions = new IdentityOptions();
            var accessClaims = new JwtSecurityTokenHandler()
                    .ReadJwtToken(access.Tokens.AccessToken.Value)
                    .Claims.ToArray();
            var accessId = accessClaims
                .FirstOrDefault(x => x.Type
                .Equals(JwtRegisteredClaimNames.Sub))
                .Value;
            var accessName = accessClaims
                .FirstOrDefault(x => x.Type
                .Equals(identityOptions.ClaimsIdentity.UserNameClaimType))
                .Value;
            var roles = accessClaims
                .Where(x => x.Type
                .Equals(ClaimTypes.Role));
            var customClaims = accessClaims
                .Where(x => customClaimsType.Contains(x.Type))
                .Select(x => new KeyValuePair<string, string>(x.Type, x.Value))
                .ToArray();

            Assert.Equal(user.id, accessId);
            Assert.Equal(user.name, accessName);
            foreach (var role in roles)
            {
                Assert.Contains(role.Value, user.roles);
            }

            foreach (var claim in customClaims)
            {
                Assert.Contains(claim, user.claims);
            }
        }

        [Fact]
        public void IssueAccessTokenWithCustomClaim_userIdNull()
        {
            var jwtService = JwtServiceFactory.Create(
                TimeSpan.FromSeconds(10),
                TimeSpan.FromMinutes(5),
                TimeSpan.FromSeconds(10));
            var user = GetUserWithCustomClaime();

            var access = jwtService
                .IssueAccessToken(null, "", user.roles, user.claims);

            var customClaimsType = user.claims.Select(x => x.Key).ToArray();

            Assert.True(access.Result == JwtTokenResult.TokenResult.Ok);
            Assert.NotNull(access.Tokens);
            Assert.NotNull(access.Tokens.AccessToken);
            Assert.NotNull(access.Tokens.RefreshToken);
            var testclaims = access.AccessClaims
                .Where(x => customClaimsType.Contains(x.Type))
                .Select(x => new KeyValuePair<string, string>(x.Type, x.Value))
                .ToArray();
            foreach (var claimPair in testclaims)
            {
                Assert.Contains(claimPair, user.claims);
            }
            var identityOptions = new IdentityOptions();
            var accessClaims = new JwtSecurityTokenHandler()
                    .ReadJwtToken(access.Tokens.AccessToken.Value)
                    .Claims.ToArray();
            var accessId = accessClaims
                .FirstOrDefault(x => x.Type
                .Equals(JwtRegisteredClaimNames.Sub))
                .Value;
            var accessName = accessClaims
                .FirstOrDefault(x => x.Type
                .Equals(identityOptions.ClaimsIdentity.UserNameClaimType))
                .Value;
            var roles = accessClaims
                .Where(x => x.Type
                .Equals(ClaimTypes.Role));
            var customClaims = accessClaims
                .Where(x => customClaimsType.Contains(x.Type))
                .Select(x => new KeyValuePair<string, string>(x.Type, x.Value))
                .ToArray();

            Assert.True(string.IsNullOrEmpty(accessId));
            Assert.True(string.IsNullOrEmpty(accessName));
            foreach (var role in roles)
            {
                Assert.Contains(role.Value, user.roles);
            }

            foreach (var claim in customClaims)
            {
                Assert.Contains(claim, user.claims);
            }
        }

        [Fact]
        public void IssueAccessToken()
        {
            var jwtService = JwtServiceFactory.Create(
                TimeSpan.FromSeconds(10),
                TimeSpan.FromMinutes(5),
                TimeSpan.FromSeconds(10));
            var user = GetUser();

            var access = jwtService
                .IssueAccessToken(user.id, user.name, user.roles);
            Assert.True(access.Result == JwtTokenResult.TokenResult.Ok);
            Assert.NotNull(access.Tokens);
            Assert.NotNull(access.Tokens.AccessToken);
            Assert.NotNull(access.Tokens.RefreshToken);

            var identityOptions = new IdentityOptions();
            var accessClaims = new JwtSecurityTokenHandler()
                    .ReadJwtToken(access.Tokens.AccessToken.Value)
                    .Claims.ToArray();
            var accessId = accessClaims
                .FirstOrDefault(x => x.Type
                .Equals(JwtRegisteredClaimNames.Sub))
                .Value;
            var accessName = accessClaims
                .FirstOrDefault(x => x.Type
                .Equals(identityOptions.ClaimsIdentity.UserNameClaimType))
                .Value;
            var roles = accessClaims
                .Where(x => x.Type
                .Equals(ClaimTypes.Role));

            Assert.Equal(user.id, accessId);
            Assert.Equal(user.name, accessName);
            foreach (var role in roles)
            {
                Assert.Contains(role.Value, user.roles);
            }
        }

        [Fact]
        public async Task IssueAndRefreshAccessTokenWithCustomClaim()
        {
            var jwtService = JwtServiceFactory.Create(
              TimeSpan.FromSeconds(10),
               TimeSpan.FromMinutes(5),
               TimeSpan.FromSeconds(10));
            var user = GetUserWithCustomClaime();
            var access = jwtService
                .IssueAccessToken(user.id, user.name, user.roles, user.claims);
            var customClaimsType = user.claims.Select(x => x.Key).ToArray();
            await Task.Delay(11000);

            var refreshedAccess = jwtService
                .RefreshAccessToken(
                    access.Tokens.AccessToken.Value,
                    access.Tokens.RefreshToken.Value);

            Assert.True(refreshedAccess.Result == JwtTokenResult.TokenResult.Ok);
            Assert.NotNull(refreshedAccess.Tokens);
            Assert.NotNull(refreshedAccess.Tokens.AccessToken);
            Assert.Null(refreshedAccess.Tokens.RefreshToken.Value);
            Assert.Equal(user.id, refreshedAccess.UserId);
            var testclaims = refreshedAccess.AccessClaims
                .Where(x => customClaimsType.Contains(x.Type))
                .Select(x => new KeyValuePair<string, string>(x.Type, x.Value))
                .ToArray();
            foreach (var claimPair in testclaims)
            {
                Assert.Contains(claimPair, user.claims);
            }

            var identityOptions = new IdentityOptions();
            var accessClaims = new JwtSecurityTokenHandler()
                    .ReadJwtToken(access.Tokens.AccessToken.Value)
                    .Claims.ToArray();
            var accessId = accessClaims
                .FirstOrDefault(x => x.Type
                .Equals(JwtRegisteredClaimNames.Sub))
                .Value;
            var accessName = accessClaims
                .FirstOrDefault(x => x.Type
                .Equals(identityOptions.ClaimsIdentity.UserNameClaimType))
                .Value;
            var roles = accessClaims
                .Where(x => x.Type
                .Equals(ClaimTypes.Role));

            Assert.Equal(user.id, accessId);
            Assert.Equal(user.name, accessName);
            foreach (var role in roles)
            {
                Assert.Contains(role.Value, user.roles);
            }
            Assert.False(access.Tokens.AccessToken
                .Equals(refreshedAccess.Tokens.AccessToken));

            var refreshedAccessClaims = new JwtSecurityTokenHandler()
                   .ReadJwtToken(refreshedAccess.Tokens.AccessToken.Value)
                   .Claims.ToArray();
            var customClaims = refreshedAccessClaims
                .Where(x => customClaimsType.Contains(x.Type))
                .Select(x => new KeyValuePair<string, string>(x.Type, x.Value))
                .ToArray();
            foreach (var claim in customClaims)
            {
                Assert.Contains(claim, user.claims);
            }
        }

        [Fact]
        public async Task IssueAndRefreshAccessToken()
        {
            var jwtService = JwtServiceFactory.Create(
              TimeSpan.FromSeconds(10),
               TimeSpan.FromMinutes(5),
               TimeSpan.FromSeconds(10));
            var user = GetUser();
            var access = jwtService
                .IssueAccessToken(user.id, user.name, user.roles);

            await Task.Delay(11000);

            var refreshedAccess = jwtService
                .RefreshAccessToken(
                    access.Tokens.AccessToken.Value,
                    access.Tokens.RefreshToken.Value);

            Assert.True(refreshedAccess.Result == JwtTokenResult.TokenResult.Ok);
            Assert.NotNull(refreshedAccess.Tokens);
            Assert.NotNull(refreshedAccess.Tokens.AccessToken);
            Assert.Null(refreshedAccess.Tokens.RefreshToken.Value);
            Assert.Equal(user.id, refreshedAccess.UserId);

            var identityOptions = new IdentityOptions();
            var accessClaims = new JwtSecurityTokenHandler()
                    .ReadJwtToken(access.Tokens.AccessToken.Value)
                    .Claims.ToArray();
            var accessId = accessClaims
                .FirstOrDefault(x => x.Type
                .Equals(JwtRegisteredClaimNames.Sub))
                .Value;
            var accessName = accessClaims
                .FirstOrDefault(x => x.Type
                .Equals(identityOptions.ClaimsIdentity.UserNameClaimType))
                .Value;
            var roles = accessClaims
                .Where(x => x.Type
                .Equals(ClaimTypes.Role));

            Assert.Equal(user.id, accessId);
            Assert.Equal(user.name, accessName);
            foreach (var role in roles)
            {
                Assert.Contains(role.Value, user.roles);
            }
            Assert.False(access.Tokens.AccessToken
                .Equals(refreshedAccess.Tokens.AccessToken));
        }

        [Fact]
        public async Task IssueAndRefreshWithSameJti()
        {
            var jwtService = JwtServiceFactory.Create(
              TimeSpan.FromSeconds(5),
               TimeSpan.FromSeconds(300),
               TimeSpan.FromSeconds(10));
            var (id, name, roles) = GetUser();
            var access = jwtService
                .IssueAccessToken(id, name, roles);

            Assert.NotNull(access.Tokens.RefreshToken);

            int index = 0;
            var accessToken = access.Tokens.AccessToken.Value;
            while (index < 4)
            {
                index++;
                await Task.Delay(TimeSpan.FromSeconds(6));

                var refreshedAccess = jwtService
                    .RefreshAccessToken(
                        accessToken,
                        access.Tokens.RefreshToken.Value);

                Assert.True(refreshedAccess.Result == JwtTokenResult.TokenResult.Ok);
                Assert.Equal(access.Tokens.RefreshToken.Jti, refreshedAccess.Tokens.RefreshToken.Jti);
                Assert.Equal(id, refreshedAccess.UserId);

                accessToken = refreshedAccess.Tokens.AccessToken.Value;
            }
        }

        [Fact]
        public async Task IssueAndRefreshUntilRefreshTokenNotExpired()
        {
            var jwtService = JwtServiceFactory.Create(
              TimeSpan.FromSeconds(5),
               TimeSpan.FromSeconds(30),
               TimeSpan.FromSeconds(10));
            var user = GetUser();
            var access = jwtService
                .IssueAccessToken(user.id, user.name, user.roles);

            Assert.NotNull(access.Tokens.RefreshToken);

            int index = 0;
            var accessToken = access.Tokens.AccessToken.Value;
            while (index < 4)
            {
                index++;
                await Task.Delay(TimeSpan.FromSeconds(6));

                var refreshedAccess = jwtService
                    .RefreshAccessToken(
                        accessToken,
                        access.Tokens.RefreshToken.Value);

                Assert.True(refreshedAccess.Result == JwtTokenResult.TokenResult.Ok);
                Assert.Equal(user.id, refreshedAccess.UserId);

                var identityOptions = new IdentityOptions();
                var accessClaims = new JwtSecurityTokenHandler()
                        .ReadJwtToken(refreshedAccess.Tokens.AccessToken.Value)
                        .Claims.ToArray();
                var accessId = accessClaims
                    .FirstOrDefault(x => x.Type
                    .Equals(JwtRegisteredClaimNames.Sub))
                    .Value;
                var accessName = accessClaims
                    .FirstOrDefault(x => x.Type
                    .Equals(identityOptions.ClaimsIdentity.UserNameClaimType))
                    .Value;
                var roles = accessClaims
                    .Where(x => x.Type
                    .Equals(ClaimTypes.Role));

                Assert.Equal(user.id, accessId);
                Assert.Equal(user.name, accessName);
                foreach (var role in roles)
                {
                    Assert.Contains(role.Value, user.roles);
                }
                Assert.False(accessToken
                    .Equals(refreshedAccess.Tokens.AccessToken.Value));

                accessToken = refreshedAccess.Tokens.AccessToken.Value;
            }

            await Task.Delay(TimeSpan.FromSeconds(20));

            var unRefreshedAccess = jwtService
                    .RefreshAccessToken(
                        accessToken,
                        access.Tokens.RefreshToken.Value);

            Assert.True(unRefreshedAccess.Result == 
                JwtTokenResult.TokenResult.RefreshTokenExpired);
        }

        [Fact]
        public async Task IssueAndCheckRefreshTokenIsExpired()
        {
            var jwtService = JwtServiceFactory.Create(
              TimeSpan.FromSeconds(5),
               TimeSpan.FromSeconds(20),
               TimeSpan.FromSeconds(5));
            var (id, name, roles) = GetUser();
            var access = jwtService
                .IssueAccessToken(id, name, roles);

            await Task.Delay(TimeSpan.FromSeconds(21));

            var unRefreshedAccess = jwtService
                    .RefreshAccessToken(
                        access.Tokens.AccessToken.Value,
                        access.Tokens.RefreshToken.Value);

            Assert.True(unRefreshedAccess.Result == 
                JwtTokenResult.TokenResult.RefreshTokenExpired);
        }

        [Fact]
        public async Task IssueAndCheckNewRefreshToken()
        {
            var jwtService = JwtServiceFactory.Create(
               TimeSpan.FromSeconds(5),
               TimeSpan.FromSeconds(20),
               TimeSpan.FromSeconds(5));
            var (id, name, roles) = GetUser();
            var access = jwtService
                .IssueAccessToken(id, name, roles);

            await Task.Delay(TimeSpan.FromSeconds(16));

            var unRefreshedAccess = jwtService
                    .RefreshAccessToken(
                        access.Tokens.AccessToken.Value,
                        access.Tokens.RefreshToken.Value);

            Assert.True(unRefreshedAccess.Result ==
                JwtTokenResult.TokenResult.Ok);
            Assert.NotNull(unRefreshedAccess.Tokens.RefreshToken);
        }

        [Fact]
        public void IssueTokenAndAssertDetails()
        {
            var jwtService = JwtServiceFactory.Create(
                TimeSpan.FromSeconds(10),
                TimeSpan.FromMinutes(5),
                TimeSpan.FromSeconds(10));
            var user = GetUserWithCustomClaime();

            var tokenModel = jwtService
                .IssueAccessToken(user.id, user.name, user.roles, user.claims);

            var tokenDetails = new JwtTokenDetails()
                .Get(tokenModel.Tokens.AccessToken.Value);

            Assert.Equal(tokenModel.Tokens.AccessToken.Expiration.ToShortTimeString(), tokenDetails.Expiration.ToShortTimeString());
            Assert.Equal(tokenModel.Tokens.AccessToken.Jti, tokenDetails.Jti);
            Assert.Equal(user.id, tokenDetails.Subject);
            Assert.All(tokenDetails.Roles, role => user.roles.Contains(role));
        }
    }
}
