using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.IdentityModel.Tokens;

namespace WebApplication1
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidateAudience = false,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = Configuration["Jwt:Issuer"],
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:Key"]))

                    };
                })
                .AddMicrosoftIdentityWebApp(Configuration, "AzureAd");

            services.AddControllersWithViews()
                .AddMicrosoftIdentityUI();

            services.AddApplicationInsightsTelemetry();

            services.AddRazorPages();

            services.AddOptions();

            services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                options.Events = new OpenIdConnectEvents
                {
                    OnTokenValidated = ctx =>
                    {
                        // claimsIdentity we want to add our roles to...
                        //ClaimsIdentity claimsIdentity = ClaimsPrincipal.Current.Identity as ClaimsIdentity;

                        //// List of claims
                        //var appRoles = new System.Collections.Generic.List<Claim>();

                        //foreach (Claim claim in ClaimsPrincipal.Current.FindAll("groups"))
                        //{
                        //    // use the OID and get a friendly name to use as the role (if it exists)
                        //    var groupStringValue = Configuration[$"AcceptedRoles:{claim.Value}"];
                        //    if (groupStringValue != null)
                        //    {
                        //        // build the list
                        //        appRoles.Add(new Claim(claimsIdentity.RoleClaimType, groupStringValue));
                        //    }
                        //}

                        //if (appRoles.Count > 0)
                        //{
                        //    // if anything in the list, add these claims to the current identity
                        //    claimsIdentity.AddClaims(appRoles);
                        //}

                        return Task.CompletedTask;
                    },
                };
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseAuthentication();

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();

            app.UseMiddleware<AuthenticationMiddleware>();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
