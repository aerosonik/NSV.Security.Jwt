namespace NSV.Security.JWT
{
    public struct JwtTokenResult
    { 
        public TokenModel Tokens { get; }
        public TokenResult Result { get; }
        public string RefreshTokenJti { get; }

        public JwtTokenResult(
            TokenResult result = TokenResult.Ok, 
            TokenModel model = null,
            string refreshTokenJti = null)
        {
            Tokens = model;
            Result = result;
            RefreshTokenJti = refreshTokenJti;
        }

        public enum TokenResult
        {
            Ok,
            RefreshTokenInvalid,
            AccessTokenInvalid,
            TokensMismatch,
            RefreshTokenExpired
        }

        internal static JwtTokenResult Ok(TokenModel model, string jti)
        {
            return new JwtTokenResult
            (
                model : model,
                result : TokenResult.Ok,
                refreshTokenJti: jti
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
