using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using coderush.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using coderush.Services.Security;
using coderush.Models;
using coderush.Services.App;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.Extensions.Hosting;

namespace coderush
{
  public class Startup
  {
    public Startup(IConfiguration configuration) { Configuration = configuration; }

    public IConfiguration Configuration { get; }

    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services)
    {
      services.Configure<CookiePolicyOptions>(options =>
      {
        // This lambda determines whether user consent for non-essential cookies is needed for a given request.
        options.CheckConsentNeeded = context => true;
        options.MinimumSameSitePolicy = SameSiteMode.None;
        options.HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.Always;
      });

      services.AddDbContext<ApplicationDbContext>(options =>
                                                    options.UseSqlServer(
                                                                         Configuration.GetConnectionString("DefaultConnection")));

      /// Get Custom Identity Default Options
      IConfigurationSection identityDefaultOptionsConfigurationSection = Configuration.GetSection("IdentityDefaultOptions");

      services.Configure<IdentityDefaultOptions>(identityDefaultOptionsConfigurationSection);

      var identityDefaultOptions = identityDefaultOptionsConfigurationSection.Get<IdentityDefaultOptions>();

      services.AddIdentity<IdentityUser, IdentityRole>(options =>
              {
                // Password settings
                options.Password.RequireDigit = identityDefaultOptions.PasswordRequireDigit;
                options.Password.RequiredLength = identityDefaultOptions.PasswordRequiredLength;
                options.Password.RequireNonAlphanumeric = identityDefaultOptions.PasswordRequireNonAlphanumeric;
                options.Password.RequireUppercase = identityDefaultOptions.PasswordRequireUppercase;
                options.Password.RequireLowercase = identityDefaultOptions.PasswordRequireLowercase;
                options.Password.RequiredUniqueChars = identityDefaultOptions.PasswordRequiredUniqueChars;

                // Lockout settings
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(identityDefaultOptions.LockoutDefaultLockoutTimeSpanInMinutes);
                options.Lockout.MaxFailedAccessAttempts = identityDefaultOptions.LockoutMaxFailedAccessAttempts;
                options.Lockout.AllowedForNewUsers = identityDefaultOptions.LockoutAllowedForNewUsers;

                // User settings
                options.User.RequireUniqueEmail = identityDefaultOptions.UserRequireUniqueEmail;

                // email confirmation require
                options.SignIn.RequireConfirmedEmail = identityDefaultOptions.SignInRequireConfirmedEmail;
              })
              //.AddDefaultUI(UIFramework.Bootstrap4)
              .AddEntityFrameworkStores<ApplicationDbContext>()
              .AddDefaultTokenProviders();


      // cookie settings
      //services.ConfigureApplicationCookie(options =>
      //{
      //  // Cookie settings
      //  options.Cookie.HttpOnly = identityDefaultOptions.CookieHttpOnly;
      //  options.ExpireTimeSpan = TimeSpan.FromDays(identityDefaultOptions.CookieExpiration);
      //  options.SlidingExpiration = identityDefaultOptions.SlidingExpiration;
      //});
      services.ConfigureApplicationCookie(options => {
        // Cookie settings  
        options.Cookie.HttpOnly = true;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.LoginPath = "/Identity/Account/Login"; // If the LoginPath is not set here, ASP.NET Core will default to /Account/Login  
        options.LogoutPath = "/Identity/Account/Logout"; // If the LogoutPath is not set here, ASP.NET Core will default to /Account/Logout  
        options.AccessDeniedPath = "/Identity/Account/AccessDenied"; // If the AccessDeniedPath is not set here, ASP.NET Core will default to /Account/AccessDenied  
        options.SlidingExpiration = true;
      });

      // lowercase url
      services.AddRouting(options => { options.LowercaseUrls = true; });
      services.AddControllersWithViews();
      services.AddMvc().AddRazorRuntimeCompilation();

      //****************************************
      // AREAS Routing WorkAround : RazorView Options/Settings
      //****************************************
      //services.Configure<RazorViewEngineOptions>(options =>
      //{
      //  options.AreaViewLocationFormats.Clear();
      //  // ORIG
      //  //options.AreaViewLocationFormats.Add("/AreaRoute/{2}/Views/{1}/{0}.cshtml");
      //  //options.AreaViewLocationFormats.Add("/AreaRoute/{2}/Views/Shared/{0}.cshtml");
      //  // NEW
      //  options.AreaViewLocationFormats.Add("/Areas/{2}/Views/{1}/{0}.cshtml");
      //  options.AreaViewLocationFormats.Add("/Areas/{2}/Views/Shared/{0}.cshtml");
      //  options.AreaViewLocationFormats.Add("/Views/Shared/{0}.cshtml");
      //});

      // register Email Service
      services.AddTransient<IEmailSender, AuthMessageSender>();

      /// Get Custom Super Admin Default options
      services.Configure<SuperAdminDefaultOptions>(Configuration.GetSection("SuperAdminDefaultOptions"));

      /// Add Custom Common Security Service
      services.AddTransient<Services.Security.ICommon, Services.Security.Common>();

      /// Add Custom Common Database servcie
      services.AddScoped<Services.Database.ICommon, Services.Database.Common>();

      services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_3_0);
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env, Services.Database.ICommon dbInit)
    {
      //custom exception handling, to catch 404
      app.Use(async (context, next) =>
      {
        await next();

        if (context.Response.StatusCode == 404 && !context.Response.HasStarted)
        {
          string originalPath = context.Request.Path.Value;
          context.Items["originalPath"] = originalPath;
          context.Request.Path = "/Error/404";
          await next();
        }
      });

      if (env.IsDevelopment())
      {
        app.UseDeveloperExceptionPage();
      }
      else
      {
        //custom exception handling to catch error 500
        app.UseExceptionHandler("/Error/500");
        // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
        app.UseHsts();
      }

      //init database with custom seed data
      //dbInit.Initialize().Wait();

      app.UseHttpsRedirection();
      app.UseStaticFiles();

      app.UseRouting();

      app.UseAuthentication();
      app.UseAuthorization();

      app.UseEndpoints(endpoints =>
      {
        endpoints.MapControllerRoute(name: "areas",
                                     pattern: "{area:exists}/{controller}/{action}/{id?}");

        endpoints.MapControllerRoute(name: "default",
                                     pattern: "{controller=Home}/{action=Index}/{id?}");

        //endpoints.MapControllers(); // enables controllers in endpoint routing
        //endpoints.MapDefaultControllerRoute(); // adds the default route {controller=Home}/{action=Index}/{id?}

        endpoints.MapRazorPages();
      });
    }
  }
}