using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CodeSignAuto.Service.Api;

public sealed class BearerTokenAuthenticationOptions : AuthenticationSchemeOptions
{
    public byte[] TokenHash { get; set; } = [];
}

public sealed class BearerTokenAuthenticationHandler : AuthenticationHandler<BearerTokenAuthenticationOptions>
{
    public const string SchemeName = "SimplySignBearer";

    public BearerTokenAuthenticationHandler(
        IOptionsMonitor<BearerTokenAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var values = Request.Headers.Authorization;
        if (values.Count != 1 || !TryReadToken(values[0], out var token))
        {
            return Task.FromResult(AuthenticateResult.Fail("invalid bearer token"));
        }

        var actual = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        if (Options.TokenHash.Length != actual.Length ||
            !CryptographicOperations.FixedTimeEquals(actual, Options.TokenHash))
        {
            return Task.FromResult(AuthenticateResult.Fail("invalid bearer token"));
        }

        var identity = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, Convert.ToHexStringLower(actual))], SchemeName);
        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.ContentType = "application/problem+json";
        await JsonSerializer.SerializeAsync(
            Response.Body,
            ApiProblem.Create("unauthorized", Context.TraceIdentifier, "Authentication is required."),
            JsonSerializerOptions.Web,
            cancellationToken: Context.RequestAborted);
    }

    private static bool TryReadToken(string? header, out string token)
    {
        token = string.Empty;
        const string prefix = "Bearer ";
        if (header is null || !header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        token = header[prefix.Length..];
        return token.Length > 0 && !token.Any(char.IsWhiteSpace) && !token.Contains(',', StringComparison.Ordinal);
    }
}
