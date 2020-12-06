using Fixit.Core.Security.Authorization.AzureFunctions.Attributes;
using Fixit.Core.Security.Authorization.AzureFunctions.Providers;
using Microsoft.Azure.WebJobs.Host.Bindings;
using System;
using System.Reflection;
using System.Threading.Tasks;

namespace Fixit.Core.Security.Authorization.AzureFunctions.Bindings
{
  /// <summary>
  /// Provides a new binding instance for the function host.
  /// </summary>
  public class AccessBindingProvider : IBindingProvider
  {
    private readonly IFixitAuthorizationProvider _fixitAuthorizationProvider;

    public AccessBindingProvider(IFixitAuthorizationProvider fixitAuthorizationProvider)
    {
      _fixitAuthorizationProvider = fixitAuthorizationProvider ?? throw new ArgumentNullException($"{nameof(AccessBindingProvider)} expects a value for {nameof(fixitAuthorizationProvider)}... null argument was provided");
    }

    public Task<IBinding> TryCreateAsync(BindingProviderContext context)
    {
      var attribute = context.Parameter.GetCustomAttribute<FixitAccessAttribute>();
      
      IBinding binding = new AccessBinding(attribute, _fixitAuthorizationProvider);
      return Task.FromResult(binding);
    }
  }
}
