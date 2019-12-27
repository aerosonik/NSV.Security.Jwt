<img src="https://raw.githubusercontent.com/aerosonik/ValidationPipe/f5997cdfaff661d36939c45823e93bb613a3767d/icon.png" alt="nsv" height="80" />

# NSV.Security.Jwt
Lightwiweigth JWT library. It can issue tokens and validate with refresing both - access/refresh tokens.

[![NuGet](https://img.shields.io/nuget/v/NSV.Security.Jwt.svg)](https://www.nuget.org/packages/NSV.Security.Jwt) 
[![Build status](https://ci.appveyor.com/api/projects/status/r3yptmhufh3dl1xc?svg=true)](https://ci.appveyor.com/project/aerosonik/nsv-security-jwt)

## Installation

Get latest stable version from [NuGet](https://www.nuget.org/packages/NSV.ExecutionPipe/).

## Features

* Issue access token
* Issue "refresh" token (use it to refresh access token)
* Refresh token - verification and creating new tokens 
* Fully configurable
* Asp .Net Core pipeline ready

## How to use it:

### Configuration

Add to appsettinegs.json file new configure section, like this:
```js
"JwtOptions": {
    "ValidIssuer": "aerosonik.identity.nsv.pub",
    "ValidAudience": "aerosonik.identity.nsv.pub",
    "AccessSecurityKey": "4f3026ab-3f9f-4190-b4e8-83ab7ae2df74@identity.nsv.pub/defaultAcessSecurityKey",
    "AccessTokenExpiry": "00.00:30:00.000", //DD.HH:mm:ss:ms
    "RefreshSecurityKey": "11bda118-9f48-426e-aedb-ff4a9ee12f1c@identity.nsv.pub/defaultRefreshSecurityKey",
    "RefreshTokenExpiry": "00.00:24:00.000", //DD.HH:mm:ss:ms
    "UpdateRefreshTokenBeforeExpired": "00.00:01:00.000" //DD.HH:mm:ss:ms
  },
```

*`ValidIssuer`, `ValidAudience` - standatd jwt configuration.
*`AccessSecurityKey` - secret seqcurity key for access token.
*`AccessTokenExpiry` - access token lifetime.
*`RefreshSecurityKey` - secret seqcurity key for "refresh" token.
*`RefreshTokenExpiry` - "refresh" token lifetime, must be greater then `AccessTokenExpiry`.
*`UpdateRefreshTokenBeforeExpired` - this field indicate when "refresh" token should be re created when `RefreshAccessToken(..)` called


Add `JwtService` it to asp .net core pipeline by using extensions method 
`IServiceCollection AddJwt(...)`
It will look's similar to
```csharp
public void ConfigureServices(IServiceCollection services)
{
  services.AddOptions();
  services.AddJwt(Configuration);
  .......
```

Or, you can configure Jwt directly in code
```csharp
public void ConfigureServices(IServiceCollection services)
{
  services.AddOptions();
  services.AddJwt(conf =>
  {
    conf.ValidIssuer = "sequrity.nsv.pub";
    conf.ValidAudience = "sequrity.nsv.pub";
    conf.AccessSecurityKey = "c12477f1-c84e-4a82-aa4d-7574ee08e592@identity.nsv.pub/defaultAcessSecurityKey";
    conf.RefreshSecurityKey = "c16455f1-c88e-4b92-bb4d-79749e989592@identity.nsv.pub/defaultRefreshSecurityKey";
    conf.AccessTokenExpiry = TimeSpan.FromMinutes(30);
    conf.RefreshTokenExpiry = TimeSpan.FromDays(5);
    conf.UpdateRefreshTokenBeforeExpired = TimeSpan.FromMinutes(30);
  });
  .......
```

If you need to use it with Asp .Net Core Authentication/authorization mechanism, just propogade to it our jwt configuration:
```csharp
services.AddAuthentication(options =>
{
  options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
  options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
  options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
  options.RequireHttpsMetadata = false;
  options.TokenValidationParameters = JwtSettings.TokenValidationParameters();
});
```
### Use it in your code

Inject registered IJwtService in your Authentication service
```csharp
public class AuthService
{
  private readonly IJwtService _jwtService;
  ...
  public Auth(IJwtService jwtService, ...)
  {
    _jwtService = jwtService;
    ...
  }
```
Login/signin case:

```csharp
public async Task<WebApiResult<TokensModel>> Signin(LogInModel model)
{
  var userResult = await _authRepository.GetUserByLogin(model.Login);
  if (userResult.Result == DataBaseResultEnum.Error) // handle 500
    return ... 

  if (userResult.Result == DataBaseResultEnum.NotFound) // handle 404
    return ...
  
  var validateResult = _passwordService.Validate(model.Password, userResult.Value.Password);
  if (validateResult.Result != PasswordValidateResult.ValidateResult.Ok) // handle 401
    return ...
            
  // Create Issue/Refresh tokens
  var jwtResult = _jwtService.IssueAccessToken(
      userResult.Value.Id.ToString(),
      userResult.Value.UserName,
      userResult.Value.Roles);

  return new WebApiResult<TokensModel>(
      HttpStatusCode.OK,
      new TokensModel
      {
        AccessToken = jwtResult.Tokens.AccessToken.Value,
        RefreshToken = jwtResult.Tokens.RefreshToken.Value
      });
}
```
Refresh case:

```csharp
public async Task<WebApiResult<TokensModel>> Refresh(TokensModel model)
{
  //try refresh
  var validatedResult = _jwtService
    .RefreshAccessToken(model.AccessToken, model.RefreshToken);
  if(validatedResult.Result != JwtTokenResult.TokenResult.Ok)// handle 401
    return ...
  return new WebApiResult<TokensModel>(
    HttpStatusCode.OK, 
    new TokensModel
    {
       AccessToken = validatedResult.Tokens.AccessToken.Value,
       RefreshToken = validatedResult.Tokens.RefreshToken?.Value // can be null? when accessToken refreshed only
    });
}
```
