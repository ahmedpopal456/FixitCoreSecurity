using Fixit.Core.Security.Authorization.AzureFunctions.Attributes;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Fixit.Core.Security.Authorization.AzureFunctions.Providers
{
  public interface IFixitAuthorizationProvider
  {
    Task<bool> AuthorizeAsync(ClaimsPrincipal claimsPricipal, FixitAccessAttribute empowerAccessAttribute);
  }
}
