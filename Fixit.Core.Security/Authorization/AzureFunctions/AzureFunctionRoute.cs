using Fixit.Core.Security.Authorization.AzureFunctions.Access;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;

namespace Fixit.Core.Security.Authorization.AzureFunctions
{
  public class AzureFunctionRoute
  {
    public AzureFunctionRoute() { }


    public IActionResult ExecuteRoute(Func<IActionResult> executingFunction, AccessResult accessResult)
    {
      if(accessResult.Status == AccessStatus.Valid)
      {
        return executingFunction.Invoke();
      }
      else
      {
        return new UnauthorizedObjectResult("Unauthorized"); 
      }
    }

    public async Task<IActionResult> ExecuteRouteAsync(Task<IActionResult> executingFunction, AccessResult accessResult)
    {
      if (accessResult.Status == AccessStatus.Valid)
      {
        return await executingFunction;
      }
      else
      {
        return new UnauthorizedObjectResult("Unauthorized");
      }
    }
  }
}
