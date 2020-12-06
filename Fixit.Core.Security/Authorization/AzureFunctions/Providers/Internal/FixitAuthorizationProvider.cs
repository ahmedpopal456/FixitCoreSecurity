using Fixit.Core.Security.Authorization.AzureFunctions.Attributes;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Fixit.Core.Security.Authorization.AzureFunctions.Providers.Internal
{
  public class FixitAuthorizationProvider : IFixitAuthorizationProvider
  {

    public FixitAuthorizationProvider()
    {
    }

    public async Task<bool> ValidateRequestAsync(ClaimsPrincipal claimsPricipal, FixitAccessAttribute fixitAccessAttribute)
    {
      bool result = false;

      if(claimsPricipal != null && fixitAccessAttribute != null)
      {
        var userClaim = claimsPricipal.Claims.Where(item => Guid.TryParse(item.Value, out Guid result) == true).SingleOrDefault(item => item.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");

        if (userClaim != null)
        {
          // TODO: Add logic that validates whether the role defined on the route coincides with the role defined within the user token 
          result = true;
        }
      }
      return result;
    }
  }
}
