namespace NSV.Security.JWT
{
    public struct JwtTokenResult
    { 
        public TokenModel Tokens { get; }
        public TokenResult Result { get; }

        public JwtTokenResult(
            TokenResult result = TokenResult.Ok, 
            TokenModel model = null)
        {
            Tokens = model;
            Result = result;
        }

        public enum TokenResult
        {
            Ok,
            RefreshTokenInvalid,
            AccessTokenInvalid,
            TokensMismatch,
            RefreshTokenExpired
        }

        internal static JwtTokenResult Ok(TokenModel model)
        {
            return new JwtTokenResult
            (
                model : model,
                result : TokenResult.Ok
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
