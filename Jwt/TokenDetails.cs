using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;

namespace NSV.Security.JWT
{
    public struct TokenDetails
    {
        private readonly Claim[] _claims;

        public TokenDetails(DateTime expiration, Claim[] claims)
        {
            _claims = claims;
            Expiration = expiration;
        }

        public string Jti => _claims
                .FirstOrDefault(x => x.Type
                    .Equals(JwtRegisteredClaimNames.Jti))?
                .Value;
        public DateTime Expiration { get; }
        public IEnumerable<Claim> Claims  => _claims;
        public IEnumerable<string> Roles => _claims
                .Where(x => x.Type
                    .Equals(ClaimTypes.Role))
                .Select(c => c.Value);
        public string Subject => _claims
                .FirstOrDefault(x => x.Type
                    .Equals(JwtRegisteredClaimNames.Sub))?
                .Value;
    }
}
