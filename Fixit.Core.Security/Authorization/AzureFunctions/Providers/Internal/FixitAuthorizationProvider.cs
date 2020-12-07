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

    public async Task<bool> AuthorizeAsync(ClaimsPrincipal claimsPricipal, FixitAccessAttribute fixitAccessAttribute)
    {
      bool result = false;

      if(claimsPricipal != null && fixitAccessAttribute != null)
      {
        // TODO: Add logic that validates whether the role defined on the route coincides with the role 
        //       defined within the user token
        
        result = true; 
      }
      return result;
    }
  }
}
