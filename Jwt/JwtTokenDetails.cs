using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("NSV.Security.Jwt.UnitTests")]
namespace NSV.Security.JWT
{
    
    internal class JwtTokenDetails : IJwtTokenDetails
    {
        public TokenDetails Get(string token)
        {
            var jwtToken = new JwtSecurityTokenHandler()
                    .ReadJwtToken(token);
            var claims = jwtToken.Claims.ToArray();
            var expiration = jwtToken.ValidTo;
            return new TokenDetails(expiration, claims);
        }
    }
}
