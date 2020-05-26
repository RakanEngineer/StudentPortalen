using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using StudentPortalen.API.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

namespace StudentPortalen.API
{
    public class Startup
    {
        readonly string MyAllowSpecificOrigins = "_myAllowSpecificOrigins";
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));
            services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
                .AddRoles<IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>();
            services.AddAuthorization(options =>
                options.AddPolicy("ShouldBeAdministrator",
                    policy => policy.RequireRole("Administrator")));

            // Restrict access to /admin for anonymous users (not logged in).
            services.AddControllersWithViews();
            services.AddRazorPages(options =>
                options.Conventions.AuthorizeAreaFolder("Admin", "/", "ShouldBeAdministrator"));
            services.AddControllers(config =>
            {
                config.ReturnHttpNotAcceptable = true; // 406 Not Acceptable
            }).AddNewtonsoftJson();

            //services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            //    .AddJwtBearer(options =>
            //    {
            //        var signingKey = Convert.FromBase64String(Configuration["Token:SigningKey"]);

            //        options.TokenValidationParameters = new TokenValidationParameters
            //        {
            //            ValidateIssuer = false,
            //            ValidateAudience = false,
            //            ValidateIssuerSigningKey = true,
            //            IssuerSigningKey = new SymmetricSecurityKey(signingKey)
            //        };
            //    });
            services.AddAuthorization(config =>
            {
                config.AddPolicy("IsAdministrator", policy =>
                policy.RequireClaim("admin"));
            });

            services.AddSwaggerGen(setupAction => {

                setupAction.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "StudentPortalen API",
                    Version = "1"
                });
                setupAction.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = @"JWT Authorization header using the Bearer scheme. \r\n\r\n 
                        Enter 'Bearer' [space] and then your token in the text input below.
                        \r\n\r\nExample: 'Bearer 12345abcdef'",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
                });

                setupAction.AddSecurityRequirement(new OpenApiSecurityRequirement()
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            },
                            Scheme = "oauth2",
                            Name = "Bearer",
                            In = ParameterLocation.Header,

                        },
                        new List<string>()
                    }
                });
            });

            services.AddCors(options =>
            {
                options.AddPolicy(name: MyAllowSpecificOrigins,
                                  builder =>
                                  {
                                      builder.WithOrigins("http://localhost:4200")
                                      .SetIsOriginAllowedToAllowWildcardSubdomains(); ;
                                  });
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
            public void Configure(IApplicationBuilder app, IWebHostEnvironment env,
                UserManager<IdentityUser> userManager,
                RoleManager<IdentityRole> roleManager)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseSwagger();

            app.UseSwaggerUI(setupAction =>
            {
                setupAction.SwaggerEndpoint("/swagger/v1/swagger.json", "StudentPortalen API v1");
            });

            app.UseRouting();

            app.UseCors(a =>
            a.SetIsOriginAllowed(x => _ = true).AllowAnyMethod().AllowAnyHeader().AllowCredentials());

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();

                endpoints.MapControllers();
            });
            MyIdentityDataInitializer.SeedData(userManager, roleManager);
        }
        public static class MyIdentityDataInitializer
        {
            public static void SeedData(
                UserManager<IdentityUser> userManager,
                RoleManager<IdentityRole> roleManager)

            {
                SeedRoles(roleManager);
                SeedUsers(userManager);
            }
            public static void SeedUsers(UserManager<IdentityUser> userManager)
            {
                if (userManager.FindByNameAsync("mustafa.ali@gmail.com").Result == null)
                {
                    IdentityUser user = new IdentityUser
                    {
                        UserName = "mustafa.ali@gmail.com",
                        Email = "mustafa.ali@gmail.com",
                        EmailConfirmed = true
                    };
                    IdentityResult result = userManager.CreateAsync(user, "Secret#123").Result;
                }
                if (userManager.FindByNameAsync("tariq.bhai@nomail.com").Result == null)
                {
                    IdentityUser user = new IdentityUser
                    {
                        UserName = "tariq.bhai@nomail.com",
                        Email = "tariq.bhai@nomail.com",
                        EmailConfirmed = true

                    };
                    IdentityResult result = userManager.CreateAsync(user, "Secret#123").Result;
                    if (result.Succeeded)
                    {
                        userManager.AddToRoleAsync(user, "Administrator").Wait();
                    }

                }
            }
            public static void SeedRoles(RoleManager<IdentityRole> roleManager)
            {
                if (!roleManager.RoleExistsAsync("Administrator").Result)
                {
                    IdentityRole role = new IdentityRole
                    {
                        Name = "Administrator"
                    };
                    IdentityResult roleResult = roleManager.CreateAsync(role).Result;
                }
            }
        }
    }
}
