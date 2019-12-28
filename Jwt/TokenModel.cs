using System;

namespace NSV.Security.JWT
{
    public class TokenModel
    {
        public TokenModel((string token, DateTime expiry) accessToken)
        {
            AccessToken = new Token 
            {
                Value = accessToken.token,
                Expiration = accessToken.expiry
            };
        }

        public TokenModel(
            (string token, DateTime expiry) accessToken,
            (string token, DateTime expiry) refreshToken)
        {
            AccessToken = new Token
            {
                Value = accessToken.token,
                Expiration = accessToken.expiry
            };
            RefreshToken = new Token
            {
                Value = refreshToken.token,
                Expiration = refreshToken.expiry
            };
        }

        public Token AccessToken { get; set; }
        public Token RefreshToken { get; set; }

        public class Token
        {
            public string Value { get; set; }
            public DateTime Expiration { get; set; }
        }
    }
}
