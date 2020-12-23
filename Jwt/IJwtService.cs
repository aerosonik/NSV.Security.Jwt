using System.Collections.Generic;

namespace NSV.Security.JWT
{
    public interface IJwtService
    {
        JwtTokenResult IssueAccessToken(
            string id,
            string name,
            IEnumerable<string> roles);

        JwtTokenResult RefreshAccessToken(
            string accessToken,
            string refreshToken);

        JwtTokenResult IssueAccessToken(
            string id,
            string name,
            IEnumerable<string> roles,
            IEnumerable<KeyValuePair<string, string>> customClaims);

        JwtTokenResult RefreshAccessToken(
            string accessToken,
            string refreshToken,
            IEnumerable<string> customClaimsType);

        TokenDetails GetTokenDetails(string token);
    }
}
