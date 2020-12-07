using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.WebJobs.Host.Bindings;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace Fixit.Core.Security.Authorization.AzureFunctions.Access.Local
{
  /// <summary>
  /// Creates a <see cref="ClaimsPrincipal"/> instance for the supplied header and configuration values.
  /// </summary>
  public class FixitAccessValueProvider : IValueProvider
  {
    private const string AUTH_HEADER_NAME = "Authorization";
    private const string BEARER_PREFIX = "Bearer ";

    private HttpRequest _request;
    private readonly Func<ClaimsPrincipal, Task<bool>> _authorizationValidator;
    private readonly JObject _authValidationInformation;


    public FixitAccessValueProvider(HttpRequest request,
                                    Func<ClaimsPrincipal, Task<bool>> authorizationValidator,
                                    JObject authValidationInformation)
    {
      _request = request ?? throw new ArgumentNullException($"{nameof(FixitAccessValueProvider)} expects a value for {nameof(request)}... null argument was provided");
      _authorizationValidator = authorizationValidator ?? throw new ArgumentNullException($"{nameof(FixitAccessValueProvider)} expects a value for {nameof(authorizationValidator)}... null argument was provided");
      _authValidationInformation = authValidationInformation ?? throw new ArgumentNullException($"{nameof(FixitAccessValueProvider)} expects a value for {nameof(authValidationInformation)}... null argument was provided");
    }

    public Task<object> GetValueAsync()
    {
      var empowerAccess = AccessResult.NoToken();

      try
      {
        // validate if token is valid
        if (_request.Headers.ContainsKey(AUTH_HEADER_NAME) &&
           _request.Headers[AUTH_HEADER_NAME].ToString().StartsWith(BEARER_PREFIX))
        {
          var result = default(ClaimsPrincipal);

          var plainToken = _request.Headers["Authorization"].ToString().Substring(BEARER_PREFIX.Length);

          var handler = new JwtSecurityTokenHandler();
          var token = handler.ReadJwtToken(plainToken);
          var tokenAudience = token.Claims.FirstOrDefault(c => c.Type == "aud")?.Value;

          if (tokenAudience == null || !_authValidationInformation.ContainsKey(tokenAudience))
          {
            AccessResult.Error(new Exception("Invalid Token"));
          }

          var tokenParams = new TokenValidationParameters
          {
            RequireSignedTokens = true,
            ValidAudience = tokenAudience,
            ValidateAudience = true,
            ValidIssuer = _authValidationInformation[tokenAudience]["Issuer"].ToString(),
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_authValidationInformation[tokenAudience]["SigningKey"].ToString()))
          };

          result = handler.ValidateToken(plainToken, tokenParams, out var securityToken);
          
          // then validate whether has proper accesses to the route
          if (_authorizationValidator.Invoke(result).Result && result != null)
          {
            empowerAccess = AccessResult.Success(plainToken, result);
          }
        }
      }
      catch (SecurityTokenExpiredException)
      {
        empowerAccess = AccessResult.Expired();
      }
      catch (Exception exception)
      {
        empowerAccess = AccessResult.Error(exception);
      }

      return Task.FromResult<object>(empowerAccess);
    }

    public Type Type => typeof(ClaimsPrincipal);

    public string ToInvokeString() => string.Empty;
  }
}
