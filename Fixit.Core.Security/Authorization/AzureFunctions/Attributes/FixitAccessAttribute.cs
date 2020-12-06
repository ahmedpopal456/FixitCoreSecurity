using Fixit.Core.Security.Authorization.Roles.Enums;
using Microsoft.Azure.WebJobs.Description;
using System;

namespace Fixit.Core.Security.Authorization.AzureFunctions.Attributes
{
  [AttributeUsage(AttributeTargets.Parameter | AttributeTargets.ReturnValue)]
  [Binding]
  public sealed class FixitAccessAttribute : Attribute
  {
    public string Name { get; set; }

    public RoleDefinition Role { get; set; }
  }
}
