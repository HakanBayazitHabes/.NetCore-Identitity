using dotNet_Core_Identitity.CustomValidation;
using dotNet_Core_Identitity.Models;
using dotNet_Core_Identitity.Service;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace dotNet_Core_Identitity
{
    public class Startup
    {
        public IConfiguration configuration { get; }
        public Startup(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<TwoFactorOptions>(configuration.GetSection("TwoFactorOptions"));
            services.AddScoped<TwoFactorService>();
            services.AddTransient<IAuthorizationHandler, ExpireDateExchangeHandler>();
            services.AddDbContext<AppIdentityDbContext>(opts =>
            {
                opts.UseSqlServer(configuration["ConnectionStrings:DefaultConnectionStrings"]);
                //opts.UseSqlServer(configuration["ConnectionStrings:DefaultAzureConnectionStrings"]);
            });

            services.AddAuthorization(opts =>
            {
                opts.AddPolicy("istanbulPolicy", policy =>
                {
                    policy.RequireClaim("city", "istanbul");
                });
                opts.AddPolicy("ViolencePolicy", policy =>
                {
                    policy.RequireClaim("violence");
                });
                opts.AddPolicy("ExchangePolicy", policy =>
                 {
                     policy.AddRequirements(new ExpireDateExchangeRequirement());
                 });
            });

            services.AddAuthentication().AddFacebook(opts =>
            {
                opts.AppId = configuration["Authentication:Facebook:AppId"];
                opts.AppSecret = configuration["Authentication:Facebook:AppSecret"];
            }).AddGoogle(opts =>
            {
                opts.ClientId = configuration["Authentication:Google:ClientID"];
                opts.ClientSecret = configuration["Authentication:Google:ClientSecret"];
            }).AddMicrosoftAccount(opts =>
            {
                opts.ClientId = configuration["Authentication:Microsoft:ClientID"];
                opts.ClientSecret = configuration["Authentication:Microsoft:ClientSecret"];
            });

            services.AddIdentity<AppUser, AppRole>(opts =>
            {
                opts.User.RequireUniqueEmail = true;
                opts.User.AllowedUserNameCharacters =
                "abcçdefgðhiýjklmnoöpqrsþtuüvwxyzABCÇDEFGHIÝJKLMNOÖPQRSÞTUÜVWXYZ0123456789._-";
                opts.Password.RequiredLength = 4;
                opts.Password.RequireNonAlphanumeric = false;
                opts.Password.RequireLowercase = false;
                opts.Password.RequireUppercase = false;
                opts.Password.RequireDigit = false;
            }).AddPasswordValidator<CustomPasswordValidator>().AddUserValidator<CustomUserValidator>().AddErrorDescriber<CustomIdentityErrorDescriber>
              ().AddEntityFrameworkStores<AppIdentityDbContext>
              ().AddDefaultTokenProviders();

            CookieBuilder cookieBuilder = new CookieBuilder();

            cookieBuilder.Name = "MyBlog";    //cookie'nin ismi
            cookieBuilder.HttpOnly = false;    //kötü niyetli kullanýcýlar cookie bilgimize eriþmesini istemediðimimzden sadece http isteiði üzerine cookie bilgisini alýrýz
            //cookieBuilder.Expiration = System.TimeSpan.FromDays(60);   //Cookie bilgisi ne kadar süre kullanýcýnnýn bilgisayarýnda kalsýn
            cookieBuilder.SameSite = SameSiteMode.Lax;   //SamesiteMode özelliðini Strict yaptýðýmýzda bir baþka siteden cookie göndermesine izin vermez, bankacýlýk uygulamalarýnda kullanýlýr , default olarak lax gelir ,lax baþka sitelerden cookie göndermelerine izin verir ,bankacýlýk gücenliðin üst düzey olduðu uygulamalarda Strict zorunluluktur.Diðer sitelerr için Lax kullanýmý daha saðlýklýdýr.
            cookieBuilder.SecurePolicy = CookieSecurePolicy.SameAsRequest;   //CookieSecurePolicy özellðini Always yaptðýmýzda cookie https'den saðlanmýþsa bundan sonra her zaman https'den kabuledecek , SameAsRequest yaptýðýmýzda http'den gelmiþse  http'den gönderir,https'den gelmiþse https'den gönderir.
            services.ConfigureApplicationCookie(opts =>
            {
                opts.ExpireTimeSpan = TimeSpan.FromDays(60);
                opts.LoginPath = new PathString("/Home/Login");     //Sadece üyelerin eriþebileceði sayfaya üye olmayan kiþiler týkladýðýnda bu sayfaya gönderilir.
                opts.LogoutPath = new PathString("/Member/LogOut"); // MemberLayout içerisinde asp-route-returnUrl="/Home/Index" gönderir, oradan da içerisinde verilen yola gider , uygulammaýza esneklik katýyor
                opts.Cookie = cookieBuilder;
                opts.SlidingExpiration = true;   //Cookie süresinin yarýsýnda kullanýcý tekrar login olursa cookie süresi yeniden baþlatýlýr
                opts.AccessDeniedPath = new PathString("/Member/AccessDenied");
            });

            services.AddScoped<IClaimsTransformation, ClaimProvider.ClaimProvider>();
            //services.AddScoped her bir request iþleminde  IClaimsTransformation ile her karþýlaþtýðýnda ClaimsProvider nesnesi üretir.
            //services.AddTransient IClaimsTransformation ile her karþýlaþtýðýnda ClaimsProvider nesnesi üretir..Performansý azaltýcý etkisi vardýr 
            //services.AddSingleton uygulama bir kez ayaða kalktýðý zaman üretilir.Program boyunca sadece bir defa üretilir
            //services.AddRazorPages();
            services.AddSession();
            services.AddMvc(); // AddMvcCore 'dan farký uygulamayla ilgili tüm servisleri kurar. AddMvcCore kurmaz sizden kurmanýzý bekler
            services.AddMvc(options => options.EnableEndpointRouting = false);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {

            //app.UseDeveloperExceptionPage(); //Sayfamýzda hata aldýðýmýz zaman o hatayla ilgili açýklayýcý veriler sunar
            //app.UseStatusCodePages(); //Özellikle içerik dönmeyen sayfalarda bilgilendiric yazýlar sunar

            //else
            //{
            //    app.UseExceptionHandler("/Error");
            //    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            //    app.UseHsts();
            //}
            //app.UseStaticFiles(); //Javascript boostrap gibi dosyalarý kullanmamýzý saðlar
            //app.UseAuthentication();
            //app.UseMvcWithDefaultRoute();
            //app.UseHttpsRedirection();

            //app.UseRouting();

            //app.UseAuthorization();

            //app.UseEndpoints(endpoints =>
            //{
            //    endpoints.MapRazorPages();
            //});
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }

            app.UseStatusCodePages();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseSession();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
