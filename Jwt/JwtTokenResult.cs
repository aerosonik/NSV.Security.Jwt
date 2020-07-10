using System.Collections.Generic;
using System.Security.Claims;

namespace NSV.Security.JWT
{
    public struct JwtTokenResult
    { 
        public TokenModel Tokens { get; }
        public TokenResult Result { get; }
        public string UserId { get; }

        public IEnumerable<Claim> AccessClaims { get; }

        internal JwtTokenResult(
            TokenResult result = TokenResult.Ok, 
            TokenModel model = null,
            string userId = null,
            IEnumerable<Claim> accessClaims = null)
        {
            Tokens = model;
            Result = result;
            UserId = userId;
            AccessClaims = accessClaims;
        }

        public enum TokenResult
        {
            Ok,
            RefreshTokenInvalid,
            AccessTokenInvalid,
            TokensMismatch,
            RefreshTokenExpired
        }

        internal static JwtTokenResult Ok(
            TokenModel model, 
            string userId, 
            IEnumerable<Claim> accessClaims)
        {
            return new JwtTokenResult
            (
                model: model,
                result: TokenResult.Ok,
                userId: userId,
                accessClaims: accessClaims
            );
        }
        internal static JwtTokenResult RefreshInvalid()
        {
            return new JwtTokenResult(TokenResult.RefreshTokenInvalid);
        }
        internal static JwtTokenResult AccessInvalid()
        {
            return new JwtTokenResult(TokenResult.AccessTokenInvalid);
        }
        internal static JwtTokenResult Mismatch()
        {
            return new JwtTokenResult(TokenResult.TokensMismatch);
        }
    }
}
