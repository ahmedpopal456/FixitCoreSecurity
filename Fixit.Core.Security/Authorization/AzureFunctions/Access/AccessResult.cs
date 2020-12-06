using System;
using System.Linq;
using System.Security.Claims;

namespace Fixit.Core.Security.Authorization.AzureFunctions.Access
{
  /// <summary>
  /// Contains the result of an access token check.
  /// </summary>
  public sealed class AccessResult
  {
    private AccessResult() { }

    /// <summary>
    /// Gets the security principal associated with a valid token.
    /// </summary>
    public ClaimsPrincipal Principal { get; private set; }

    /// <summary>
    /// Gets the access token associated to the request
    /// </summary>
    public string AccessToken { get; private set; }

    /// <summary>
    /// Gets the User Principal Name (id), of the user making the requesting 
    /// </summary>
    public string UserPrincipalName { get; private set; }

    /// <summary>
    /// Gets the status of the token, i.e. whether it is valid.
    /// </summary>
    public AccessStatus Status { get; private set; }

    /// <summary>
    /// Gets any exception encountered when validating a token.
    /// </summary>
    public Exception Exception { get; private set; }

    /// <summary>
    /// Returns a valid token.
    /// </summary>
    public static AccessResult Success(string accessToken, ClaimsPrincipal principal)
    {
      var user = principal.FindAll(ClaimTypes.NameIdentifier).FirstOrDefault(item => Guid.TryParse(item.Value, out Guid result));

      return new AccessResult
      {
        Principal = principal,
        Status = AccessStatus.Valid,
        AccessToken = accessToken,
        UserPrincipalName = user == null ? string.Empty : user.Value
      };
    }

    /// <summary>
    /// Returns a result that indicates the submitted token has expired.
    /// </summary>
    public static AccessResult Expired()
    {
      return new AccessResult
      {
        Status = AccessStatus.Expired
      };
    }

    /// <summary>
    /// Returns a result to indicate that there was an error when processing the token.
    /// </summary>
    public static AccessResult Error(Exception ex)
    {
      return new AccessResult
      {
        Status = AccessStatus.Error,
        Exception = ex
      };
    }

    /// <summary>
    /// Returns a result in response to no token being in the request.
    /// </summary>
    /// <returns></returns>
    public static AccessResult NoToken()
    {
      return new AccessResult
      {
        Status = AccessStatus.NoToken
      };
    }
  }
}
