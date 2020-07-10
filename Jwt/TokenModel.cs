using System;

namespace NSV.Security.JWT
{
    public class TokenModel
    {
        public TokenModel(
            (string token, DateTime expiry, string jti, string refreshJti) accessToken)
        {
            AccessToken = new Token(
                accessToken.token,
                accessToken.expiry,
                accessToken.jti
            );
            RefreshToken = new Token(accessToken.refreshJti);
        }

        public TokenModel(
            (string token, DateTime expiry, string jti) accessToken,
            (string token, DateTime expiry, string jti) refreshToken)
        {
            AccessToken = new Token(        
                accessToken.token,
                accessToken.expiry,
                accessToken.jti
            );
            RefreshToken = new Token(
                refreshToken.token,
                refreshToken.expiry,
                refreshToken.jti
            );
        }

        public Token AccessToken { get; set; }
        public Token RefreshToken { get; set; }

        public class Token
        {
            public Token(string value, DateTime expiration, string jti)
            {
                Value = value;
                Jti = jti;
                Expiration = expiration;
            }
            public Token(string jti)
            {
                Jti = jti;
            }
            public string Value { get; }
            public DateTime Expiration { get; }
            public string Jti { get; }
        }
    }
}
