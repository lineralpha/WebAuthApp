using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// this has a good high-level description about aps.net core authentication
// https://www.reddit.com/r/dotnet/comments/we9qx8/a_comprehensive_overview_of_authentication_in/
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        //options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = "GoogleOpenID";
    })
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/denied";
        options.Events = new CookieAuthenticationEvents()
        {
            OnSigningIn = async context =>
            {
                var principal = context.Principal;
                if (principal.HasClaim(c => c.Type == ClaimTypes.NameIdentifier))
                {
                    if (principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)!.Value == "jones")
                    {
                        var identity = principal.Identity as ClaimsIdentity;
                        identity.AddClaim(new Claim(ClaimTypes.Role, "Admin"));
                    }
                }
                await Task.CompletedTask;
            },
            OnSignedIn = async context =>
            {
                await Task.CompletedTask;
            },
            OnValidatePrincipal = async context =>
            {
                await Task.CompletedTask;
            }
        };
    })
    /**
    .AddGoogle(options =>
    {
        options.ClientId = builder.Configuration["Authentication:Google:ClientId"] ?? string.Empty;
        options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"] ?? string.Empty;
        options.CallbackPath = "/google/auth";

        // additional claims
        options.ClaimActions.MapJsonKey("urn:google:picture", "picture", "url");
        options.ClaimActions.MapJsonKey("urn:google:locale", "locale", "string");

        // save tokens to cookie.
        options.SaveTokens = true;

        //options.AuthorizationEndpoint += "?prompt=consent"; // <= broken in .NET 8
        // work around the above issue
        // https://github.com/dotnet/aspnetcore/issues/47054#issuecomment-1786192809
        options.Events.OnRedirectToAuthorizationEndpoint =
            context =>
            {
                context.RedirectUri += "&prompt=consent";
                context.Response.Redirect(context.RedirectUri);
                return Task.CompletedTask;
            };

        options.Events.OnCreatingTicket =
            context =>
            {
                var tokens = context.Properties.GetTokens().ToList();
                tokens.Add(new AuthenticationToken()
                {
                    Name = "TicketCreated",
                    Value = DateTime.UtcNow.ToString()
                });
                context.Properties.StoreTokens(tokens);
                return Task.CompletedTask;
            };

        options.Events.OnRemoteFailure = context =>
        {
            var authProperties = options.StateDataFormat.Unprotect(context.Request.Query["state"]);
            // failure on auth server - user may cancel auth.
            // redirect to a safe page (here homepage)
            context.Response.Redirect("/");

            // this discontinues auth processing - but no good.
            context.HandleResponse();
            return Task.CompletedTask;
        };

        //options.ReturnUrlParameter; default: "ReturnUrl"
    })
    */
    // use your own scheme name
    .AddOpenIdConnect("GoogleOpenID", options =>
    {
        options.Authority = "https://accounts.google.com";
        options.ClientId = builder.Configuration["Authentication:Google:ClientId"] ?? string.Empty;
        options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"] ?? string.Empty;
        options.CallbackPath = "/google/auth";
        options.Scope.Add("email");

        options.SaveTokens = true;

        options.Events = new OpenIdConnectEvents()
        {
            OnTokenValidated = ctx =>
            {
                var claims = ctx.Principal.Claims;
                var identity = ctx.Principal.Identity as ClaimsIdentity;
                identity.AddClaim(
                    new Claim(ClaimTypes.Role, "Admin")
                );

                return Task.CompletedTask;
            }
        };
    });


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
