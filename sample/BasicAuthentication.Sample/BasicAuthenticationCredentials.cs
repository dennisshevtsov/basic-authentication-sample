// Copyright (c) Dennis Shevtsov. All rights reserved.
// Licensed under the MIT License.
// See LICENSE in the project root for license information.

using System.ComponentModel.DataAnnotations;

namespace BasicAuthentication.Sample;

public sealed class BasicAuthenticationCredentials
{
  public const string SectionName = "BasicAuthenticationCredentials";

  [Required]
  public string? Username { get; set; }

  [Required]
  public string? Password { get; set; }

  public bool HasAccess(string username, string password) => Username == username && Password == password;
}
