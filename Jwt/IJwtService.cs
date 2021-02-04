using System.Collections.Generic;

namespace NSV.Security.JWT
{
    public interface IJwtService
    {
        JwtTokenResult IssueAccessToken(
            string id,
            string name,
            IEnumerable<string> roles,
            bool longTermRefresh = false);

        JwtTokenResult RefreshAccessToken(
            string accessToken,
            string refreshToken);

        JwtTokenResult IssueAccessToken(
            string id,
            string name,
            IEnumerable<string> roles,
            IEnumerable<KeyValuePair<string, string>> customClaims,
            bool longTermRefresh = false);

        JwtTokenResult RefreshAccessToken(
            string accessToken,
            string refreshToken,
            IEnumerable<string> customClaimsType);
    }
}
