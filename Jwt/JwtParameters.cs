using Microsoft.IdentityModel.Tokens;

namespace NSV.Security.JWT
{
    public static class JwtParameters
    {
        internal static JwtOptions Options { get; set; }

        public static TokenValidationParameters TokenValidationParameters()
        {
            if (Options == null)
                return new JwtOptions()
                    .GetAccessTokenValidationParameters();

            return Options
                    .GetAccessTokenValidationParameters();
        }
    }
}
