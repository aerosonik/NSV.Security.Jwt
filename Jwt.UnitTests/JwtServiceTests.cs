using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using NSV.Security.JWT;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;
using System.IdentityModel.Tokens.Jwt;

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
                    .ReadJwtToken(access.Tokens.AccessToken)
                    .Claims.ToArray();
            var accessId = accessClaims
                .FirstOrDefault(x => x.Type
                .Equals(identityOptions.ClaimsIdentity.UserIdClaimType))
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
                    access.Tokens.AccessToken,
                    access.Tokens.RefreshToken);

            Assert.True(refreshedAccess.Result == JwtTokenResult.TokenResult.Ok);
            Assert.NotNull(refreshedAccess.Tokens);
            Assert.NotNull(refreshedAccess.Tokens.AccessToken);
            Assert.Null(refreshedAccess.Tokens.RefreshToken);

            var identityOptions = new IdentityOptions();
            var accessClaims = new JwtSecurityTokenHandler()
                    .ReadJwtToken(access.Tokens.AccessToken)
                    .Claims.ToArray();
            var accessId = accessClaims
                .FirstOrDefault(x => x.Type
                .Equals(identityOptions.ClaimsIdentity.UserIdClaimType))
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
        public async Task IssueAndRefreshUntilRefreshTokenNotExpired()
        {
            var jwtService = JwtServiceFactory.Create(
              TimeSpan.FromSeconds(5),
               TimeSpan.FromSeconds(30),
               TimeSpan.FromSeconds(10));
            var user = GetUser();
            var access = jwtService
                .IssueAccessToken(user.id, user.name, user.roles);

            int index = 0;
            var accessToken = access.Tokens.AccessToken;
            while (index < 4)
            {
                index++;
                await Task.Delay(TimeSpan.FromSeconds(6));

                var refreshedAccess = jwtService
                    .RefreshAccessToken(
                        accessToken,
                        access.Tokens.RefreshToken);

                Assert.True(refreshedAccess.Result == JwtTokenResult.TokenResult.Ok);

                var identityOptions = new IdentityOptions();
                var accessClaims = new JwtSecurityTokenHandler()
                        .ReadJwtToken(refreshedAccess.Tokens.AccessToken)
                        .Claims.ToArray();
                var accessId = accessClaims
                    .FirstOrDefault(x => x.Type
                    .Equals(identityOptions.ClaimsIdentity.UserIdClaimType))
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
                    .Equals(refreshedAccess.Tokens.AccessToken));

                accessToken = refreshedAccess.Tokens.AccessToken;
            }

            await Task.Delay(TimeSpan.FromSeconds(20));

            var unRefreshedAccess = jwtService
                    .RefreshAccessToken(
                        accessToken,
                        access.Tokens.RefreshToken);

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
                        access.Tokens.AccessToken,
                        access.Tokens.RefreshToken);

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
                        access.Tokens.AccessToken,
                        access.Tokens.RefreshToken);

            Assert.True(unRefreshedAccess.Result ==
                JwtTokenResult.TokenResult.Ok);
            Assert.NotNull(unRefreshedAccess.Tokens.RefreshToken);
        }
    }
}
