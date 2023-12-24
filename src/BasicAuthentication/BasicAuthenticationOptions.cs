// Copyright (c) Dennis Shevtsov. All rights reserved.
// Licensed under the MIT License.
// See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace BasicAuthentication;

public sealed class BasicAuthenticationOptions : AuthenticationSchemeOptions
{
  public Func<IServiceProvider, string, string, Task<ClaimsPrincipal?>>? AuthenticateAsync { get; set; }
}
