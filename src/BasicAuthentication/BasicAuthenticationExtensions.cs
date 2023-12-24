// Copyright (c) Dennis Shevtsov. All rights reserved.
// Licensed under the MIT License.
// See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;

namespace BasicAuthentication;

public static class BasicAuthenticationExtensions
{
  public static AuthenticationBuilder AddBasicAuthentication(this AuthenticationBuilder builder, Action<BasicAuthenticationOptions> configureOptions)
  {
    ArgumentNullException.ThrowIfNull(builder);
    ArgumentNullException.ThrowIfNull(configureOptions);

    builder.AddScheme<BasicAuthenticationOptions, BasicAuthenticationHandler>(BasicAuthenticationDefaults.AuthenticationScheme, null, configureOptions);

    return builder;
  }
}
