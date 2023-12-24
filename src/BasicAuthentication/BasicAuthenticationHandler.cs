// Copyright (c) Dennis Shevtsov. All rights reserved.
// Licensed under the MIT License.
// See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace BasicAuthentication;

public sealed class BasicAuthenticationHandler(
  IOptionsMonitor<BasicAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
  : AuthenticationHandler<BasicAuthenticationOptions>(options, logger, encoder, clock)
{
  private const int StackBufferLength = 256;

  protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
  {
    if (!Request.Headers.TryGetValue(HeaderNames.Authorization, out StringValues authorizationHeader))
    {
      Logger.LogWarning("No authentication header.");
      return AuthenticateResult.NoResult();
    }

    if (!AuthenticationHeaderValue.TryParse(authorizationHeader, out AuthenticationHeaderValue? authenticationHeaderValue) ||
      authenticationHeaderValue is null)
    {
      Logger.LogWarning("No authentication header value.");
      return AuthenticateResult.NoResult();
    }

    if (authenticationHeaderValue.Scheme != BasicAuthenticationDefaults.AuthenticationScheme)
    {
      Logger.LogWarning("Another authentication scheme instead basic: {Scheme}.", authenticationHeaderValue.Scheme);
      return AuthenticateResult.NoResult();
    }

    if (string.IsNullOrEmpty(authenticationHeaderValue.Parameter))
    {
      Logger.LogWarning("No basic authentication token.");
      return AuthenticateResult.NoResult();
    }

    if (!TryParseToken(authenticationHeaderValue.Parameter, out string? username, out string? password))
    {
      return AuthenticateResult.NoResult();
    }

    if (Options.AuthenticateAsync is null)
    {
      throw new InvalidOperationException("No authentication method.");
    }

    ClaimsPrincipal? principal = await Options.AuthenticateAsync(Context.RequestServices, username, password);

    if (principal is null)
    {
      Logger.LogWarning("Invalid basic authentication credentials.");
      return AuthenticateResult.Fail("Invalid basic authentication credentials.");
    }

    AuthenticationTicket authenticationTicket = new(principal, BasicAuthenticationDefaults.AuthenticationScheme);

    return AuthenticateResult.Success(authenticationTicket);
  }

  private bool TryParseToken(
    string token,
    [NotNullWhen(returnValue: true)] out string? username,
    [NotNullWhen(returnValue: true)] out string? password)
  {
    username = null;
    password = null;

    // Each char is encoded with 6 bits. 8 bits is one byte.
    int base64BufferLength = token.Length * 6 >> 3;

    byte[]? pooledArray = null;
    Span<byte> buffer = base64BufferLength <= StackBufferLength ?
                        stackalloc byte[StackBufferLength] :
                        (pooledArray = ArrayPool<byte>.Shared.Rent(base64BufferLength));

    string usernameAndPassword;

    try
    {
      if (!Convert.TryFromBase64String(token, buffer, out int bytesWritten))
      {
        Logger.LogWarning("Invalid basic authentication token encoding.");
        return false;
      }

      buffer = buffer[..bytesWritten];
      usernameAndPassword = Encoding.UTF8.GetString(buffer);
    }
    catch (Exception ex)
    {
      Logger.LogError(ex, "Error occured while trying retreive basic authenticastion credentials.");
      return false;
    }
    finally
    {
      if (pooledArray is not null)
      {
        ArrayPool<byte>.Shared.Return(pooledArray);
      }
    }

    int separatorIndex = usernameAndPassword.IndexOf(':');

    if (separatorIndex == -1)
    {
      Logger.LogWarning("Invalid basic authentication token format.");
      return false;
    }

    username = usernameAndPassword[..separatorIndex];
    password = usernameAndPassword[(separatorIndex + 1)..];

    return true;
  }
}
