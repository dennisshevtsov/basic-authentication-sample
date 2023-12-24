// Copyright (c) Dennis Shevtsov. All rights reserved.
// Licensed under the MIT License.
// See LICENSE in the project root for license information.

using BasicAuthentication;
using BasicAuthentication.Sample;
using Microsoft.Extensions.Options;
using System.Security.Claims;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
builder.Services.AddOptions<BasicAuthenticationCredentials>()
                .Bind(builder.Configuration.GetSection(BasicAuthenticationCredentials.SectionName))
                .ValidateDataAnnotations();
builder.Services.AddAuthentication(BasicAuthenticationDefaults.AuthenticationScheme)
                .AddBasicAuthentication(options => options.AuthenticateAsync = (provider, username, password) =>
                {
                  BasicAuthenticationCredentials credentials = provider.GetRequiredService<IOptions<BasicAuthenticationCredentials>>().Value;

                  if (!credentials.HasAccess(username, password))
                  {
                    return Task.FromResult<ClaimsPrincipal?>(null);
                  }

                  ClaimsIdentity identity = new(BasicAuthenticationDefaults.AuthenticationScheme);
                  identity.AddClaim(new Claim(type: ClaimTypes.Name, value: username));

                  ClaimsPrincipal principal = new(identity);

                  return Task.FromResult<ClaimsPrincipal?>(principal);
                });
builder.Services.AddAuthorization();

WebApplication app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/", () => "Hello World!")
   .RequireAuthorization();
app.Run();
