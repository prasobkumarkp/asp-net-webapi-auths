using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Endpoint.Api;

public class SessionIdAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public SessionIdAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock)
        : base(options, logger, encoder, clock) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Check for Authorization header
        if (!Request.Headers.TryGetValue("Authorization", out var authorizationHeader) ||
            authorizationHeader != "Id")
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        // Validate session ID (replace with real validation logic)
        var claims = new[] { new Claim(ClaimTypes.Name, "SessionUser") };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}