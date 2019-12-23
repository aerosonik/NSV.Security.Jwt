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
    }
}
