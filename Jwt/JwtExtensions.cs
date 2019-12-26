using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace NSV.Security.JWT
{
    public static class JwtExtensions
    {
        public static IServiceCollection AddJwt(
            this IServiceCollection serviceCollection)
        {
            //JwtParameters.Options =  new JwtOptions();
            //serviceCollection.Configure<JwtOptions>(conf => conf = Jwt.Options);
            return serviceCollection.AddSingleton<IJwtService>(provider => 
            {
                return new JwtService(JwtSettings.Options);
            });
        }

        public static IServiceCollection AddJwt(
            this IServiceCollection serviceCollection,
            IConfiguration configuration)
        {
            JwtSettings.Options = configuration
                .GetSection(nameof(JwtOptions))
                .Get<JwtOptions>();
            //serviceCollection.Configure<JwtOptions>(conf => conf = Jwt.Options);
            return serviceCollection.AddSingleton<IJwtService>(provider =>
            {
                return new JwtService(JwtSettings.Options);
            });
        }

        public static IServiceCollection AddJwt(
            this IServiceCollection serviceCollection,
            Action<JwtOptions> configureOptions)
        {
            //JwtSettitngs.Options = new JwtOptions();
            configureOptions.Invoke(JwtSettings.Options);
            //serviceCollection.Configure<JwtOptions>(conf => conf = Jwt.Options);
            return serviceCollection.AddSingleton<IJwtService>(provider =>
            {
                return new JwtService(JwtSettings.Options);
            });
        }
    }
}
