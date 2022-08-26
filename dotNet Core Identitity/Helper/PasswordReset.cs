using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace dotNet_Core_Identitity.Helper
{
    public class PasswordReset
    {
        public static void PasswordResetSendEmail(string link,string email)
        {
            MailMessage mail = new MailMessage();

            SmtpClient smtpClient = new SmtpClient("smtp.yandex.com", 587);
            smtpClient.EnableSsl = true;
            smtpClient.DeliveryMethod = SmtpDeliveryMethod.Network;
            smtpClient.Credentials = new System.Net.NetworkCredential("your email", "your email password");

            mail.From = new MailAddress("your email");
            mail.To.Add(email);


            mail.Subject = $"www.bodybody.com:::Şifre Sıfırlama";
            mail.Body = "<h2>Şifrenizi yenilemek için lütfen aşağıdaki linke tıklayınız.</h2><hr/>";
            mail.Body += $"<a href='{link}'> şifre yenileme linki</a>";
            mail.IsBodyHtml = true;


            mail.SubjectEncoding = System.Text.Encoding.UTF8;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
            smtpClient.Send(mail);
        }
    }
}
