using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Hosting;
using System;

namespace Fixit.Core.Security.Authorization.AzureFunctions.Extensions
{
  /// <summary>
  /// Called from Startup to load the custom binding when the Azure Functions host starts up.
  /// </summary>
  public class AccessExtension : IWebJobsStartup
  {
    public void Configure(IWebJobsBuilder builder)
    {
      if (builder == null)
      {
        throw new ArgumentNullException(nameof(builder));
      }

      builder.AddExtension<AccessExtensionProvider>();
    }
  }
}
