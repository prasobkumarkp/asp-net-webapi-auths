using System.Text;
using Endpoint.Api;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "YourIssuer",
            ValidAudience = "YourAudience",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("YourSecretKey"))
        };
    });
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme; // Default
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddCookie("CookieAuth", options =>
    {
        options.Cookie.Name = "MyAppCookie";
        options.LoginPath = "/auth/login";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        // Handle authentication failure
        options.Events = new CookieAuthenticationEvents
        {
            OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            },
            OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            },
            // Validate the custom cookie
            OnValidatePrincipal = async context =>
            {
                var userPrincipal = context.Principal;

                // Example: Retrieve a custom claim
                var userIdClaim = userPrincipal?.FindFirst("UserId")?.Value;

                if (string.IsNullOrEmpty(userIdClaim))
                {
                    // Invalidate cookie if the UserId claim is missing
                    context.RejectPrincipal();
                    await context.HttpContext.SignOutAsync("CookieAuth");
                }

                // Example: Validate against the database
                var isValidUser = await ValidateUserAsync(userIdClaim!); // Replace with your validation logic
                if (!isValidUser)
                {
                    context.RejectPrincipal();
                    await context.HttpContext.SignOutAsync("CookieAuth");
                }
            }
        };
    })
    .AddScheme<AuthenticationSchemeOptions, SessionIdAuthenticationHandler>("SessionId", null);
// Add a policy for cookie-only endpoints
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CookieOnly", policy =>
        policy.AddAuthenticationSchemes("CookieAuth").RequireAuthenticatedUser());
}); // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers().RequireAuthorization();

app.Run();

return;
async Task<bool> ValidateUserAsync(string userId)
{
    // Replace this with your actual validation logic (e.g., database check)
    // Example: Check if the user exists in the database and is active
    //bool userExists = await Database.CheckUserExistsAsync(userId); // Replace with your actual DB check
    return true;
}