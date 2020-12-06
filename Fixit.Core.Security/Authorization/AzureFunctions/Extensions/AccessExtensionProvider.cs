using Fixit.Core.Security.Authorization.AzureFunctions.Attributes;
using Fixit.Core.Security.Authorization.AzureFunctions.Bindings;
using Fixit.Core.Security.Authorization.AzureFunctions.Providers;
using Microsoft.Azure.WebJobs.Host.Config;

namespace Fixit.Core.Security.Authorization.AzureFunctions.Extensions
{

  /// <summary>
  /// Wires up the attribute to the custom binding.
  /// </summary>
  public class AccessExtensionProvider : IExtensionConfigProvider
  {
    private readonly IFixitAuthorizationProvider _fixitAuthorizationProvider;

    public AccessExtensionProvider(IFixitAuthorizationProvider fixitAuthorizationProvider)
    {
      _fixitAuthorizationProvider = fixitAuthorizationProvider;
    }

    public void Initialize(ExtensionConfigContext context)
    {
      // Creates a rule that links the attribute to the binding

      var provider = new AccessBindingProvider(_fixitAuthorizationProvider);
      var rule = context.AddBindingRule<FixitAccessAttribute>().Bind(provider);
    }
  }
}
