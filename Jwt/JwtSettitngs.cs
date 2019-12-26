using Microsoft.IdentityModel.Tokens;

namespace NSV.Security.JWT
{
    public static class JwtSettings
    {
        internal static JwtOptions Options { get; set; } = new JwtOptions();

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
