using Fixit.Core.Security.Authorization.AzureFunctions.Access.Local;
using Fixit.Core.Security.Authorization.AzureFunctions.Attributes;
using Fixit.Core.Security.Authorization.AzureFunctions.Providers;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.WebJobs.Host.Bindings;
using Microsoft.Azure.WebJobs.Host.Protocols;
using Newtonsoft.Json.Linq;
using System;
using System.Threading.Tasks;

namespace Fixit.Core.Security.Authorization.AzureFunctions.Bindings
{
  /// <summary>
  /// Runs on every request and passes the function context (e.g. Http request and host configuration) to a value provider.
  /// </summary>
  public class AccessBinding : IBinding
  {
    private readonly FixitAccessAttribute _fixitAccessAttribute;
    private readonly IFixitAuthorizationProvider _fixitAuthorizationProvider;

    public AccessBinding(FixitAccessAttribute fixitAccessAttribute, IFixitAuthorizationProvider fixitAuthorizationProvider)
    {
      _fixitAccessAttribute = fixitAccessAttribute ?? throw new ArgumentNullException($"{nameof(AccessBinding)} expects a value for {nameof(fixitAccessAttribute)}... null argument was provided");
      _fixitAuthorizationProvider = fixitAuthorizationProvider ?? throw new ArgumentNullException($"{nameof(AccessBinding)} expects a value for {nameof(fixitAuthorizationProvider)}... null argument was provided");
    }

    public Task<IValueProvider> BindAsync(BindingContext context)
    {
      // get the HTTP request
      var request = context.BindingData["httpRequest"] as HttpRequest;

      // get the configuration items set for the OAuth token issuer
      var authValidationInformation = JObject.Parse(Environment.GetEnvironmentVariable("AuthorizationValidation"));

      return Task.FromResult<IValueProvider>(new FixitAccessValueProvider(request, (claimsPrincipal) => _fixitAuthorizationProvider.AuthorizeAsync(claimsPrincipal, _fixitAccessAttribute), authValidationInformation));
    }

    public bool FromAttribute => true;

    public Task<IValueProvider> BindAsync(object value, ValueBindingContext context) => null;

    public ParameterDescriptor ToParameterDescriptor() => new ParameterDescriptor();
  }
}
