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
                "abc�defg�hi�jklmno�pqrs�tu�vwxyzABC�DEFGHI�JKLMNO�PQRS�TU�VWXYZ0123456789._-";
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
            cookieBuilder.HttpOnly = false;    //k�t� niyetli kullan�c�lar cookie bilgimize eri�mesini istemedi�imimzden sadece http istei�i �zerine cookie bilgisini al�r�z
            //cookieBuilder.Expiration = System.TimeSpan.FromDays(60);   //Cookie bilgisi ne kadar s�re kullan�c�nn�n bilgisayar�nda kals�n
            cookieBuilder.SameSite = SameSiteMode.Lax;   //SamesiteMode �zelli�ini Strict yapt���m�zda bir ba�ka siteden cookie g�ndermesine izin vermez, bankac�l�k uygulamalar�nda kullan�l�r , default olarak lax gelir ,lax ba�ka sitelerden cookie g�ndermelerine izin verir ,bankac�l�k g�cenli�in �st d�zey oldu�u uygulamalarda Strict zorunluluktur.Di�er sitelerr i�in Lax kullan�m� daha sa�l�kl�d�r.
            cookieBuilder.SecurePolicy = CookieSecurePolicy.SameAsRequest;   //CookieSecurePolicy �zell�ini Always yapt��m�zda cookie https'den sa�lanm��sa bundan sonra her zaman https'den kabuledecek , SameAsRequest yapt���m�zda http'den gelmi�se  http'den g�nderir,https'den gelmi�se https'den g�nderir.
            services.ConfigureApplicationCookie(opts =>
            {
                opts.ExpireTimeSpan = TimeSpan.FromDays(60);
                opts.LoginPath = new PathString("/Home/Login");     //Sadece �yelerin eri�ebilece�i sayfaya �ye olmayan ki�iler t�klad���nda bu sayfaya g�nderilir.
                opts.LogoutPath = new PathString("/Member/LogOut"); // MemberLayout i�erisinde asp-route-returnUrl="/Home/Index" g�nderir, oradan da i�erisinde verilen yola gider , uygulamma�za esneklik kat�yor
                opts.Cookie = cookieBuilder;
                opts.SlidingExpiration = true;   //Cookie s�resinin yar�s�nda kullan�c� tekrar login olursa cookie s�resi yeniden ba�lat�l�r
                opts.AccessDeniedPath = new PathString("/Member/AccessDenied");
            });

            services.AddScoped<IClaimsTransformation, ClaimProvider.ClaimProvider>();
            //services.AddScoped her bir request i�leminde  IClaimsTransformation ile her kar��la�t���nda ClaimsProvider nesnesi �retir.
            //services.AddTransient IClaimsTransformation ile her kar��la�t���nda ClaimsProvider nesnesi �retir..Performans� azalt�c� etkisi vard�r 
            //services.AddSingleton uygulama bir kez aya�a kalkt��� zaman �retilir.Program boyunca sadece bir defa �retilir
            //services.AddRazorPages();
            services.AddSession();
            services.AddMvc(); // AddMvcCore 'dan fark� uygulamayla ilgili t�m servisleri kurar. AddMvcCore kurmaz sizden kurman�z� bekler
            services.AddMvc(options => options.EnableEndpointRouting = false);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {

            //app.UseDeveloperExceptionPage(); //Sayfam�zda hata ald���m�z zaman o hatayla ilgili a��klay�c� veriler sunar
            //app.UseStatusCodePages(); //�zellikle i�erik d�nmeyen sayfalarda bilgilendiric yaz�lar sunar

            //else
            //{
            //    app.UseExceptionHandler("/Error");
            //    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            //    app.UseHsts();
            //}
            //app.UseStaticFiles(); //Javascript boostrap gibi dosyalar� kullanmam�z� sa�lar
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
