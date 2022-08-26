using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace dotNet_Core_Identitity.Service
{
    public class EmailSender
    {
        private readonly TwoFactorOptions _twoFactorOptions;
        private readonly TwoFactorService _twoFactorService;

        public EmailSender(IOptions<TwoFactorOptions> options, TwoFactorService twoFactorService)//IOptions appsettings.json dosyasına erişir
        {
            _twoFactorOptions = options.Value;
            _twoFactorService = twoFactorService;
        }

        public string Send(string email)
        {
            string code = _twoFactorService.GetCodeVerification().ToString();

            Execute(email, code).Wait(); 
            return code;
        }

        private async Task Execute(string email,string code)
        {
            var client = new SendGridClient(_twoFactorOptions.SendGrid_ApiKey);
            var from = new EmailAddress("your email");
            var subject = "İki Adımlı Doğrulama Kodunuz";
            var to = new EmailAddress(email);
            var htmlContent = $"<h2>Siteye giriş yapabilmek için doğrulama kodunuz aşağıdadır.</h2><h3>Kodunuz:{code}</h3>";
            var msg = MailHelper.CreateSingleEmail(from, to, subject, null, htmlContent);
            var response = await client.SendEmailAsync(msg);
        }
    }
}
