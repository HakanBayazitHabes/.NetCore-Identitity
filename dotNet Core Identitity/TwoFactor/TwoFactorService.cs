using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace dotNet_Core_Identitity.Service
{
    public class TwoFactorService
    {
        private readonly UrlEncoder _urlEncoder;
        private readonly TwoFactorOptions _twoFactorOptions;


        public TwoFactorService(UrlEncoder urlEncoder, IOptions<TwoFactorOptions> options)
        {
            _urlEncoder = urlEncoder;
            _twoFactorOptions = options.Value;
        }
        public int GetCodeVerification()
        {
            Random random = new Random();
            return random.Next(1000, 9999);
        }

        public int TimeLeft(HttpContext context)//Httpcontext ile session'a ulaşırız
        {
            if (context.Session.GetString("currentTime") == null)
            {
                context.Session.SetString("currentTime", DateTime.Now.AddSeconds(_twoFactorOptions.CodeTimeExpire).ToString());
            }

            DateTime currentTime = DateTime.Parse(context.Session.GetString("currentTime").ToString());

            int timeLeft = (int)(currentTime - DateTime.Now).TotalSeconds;
            if (timeLeft <= 0)
            {
                context.Session.Remove("currentTime");
                return 0;
            }
            else
            {
                return timeLeft;
            }
        }

        public string GenerateQrCodeUri(string email, string unformattedKey)
        {
            const string format = "otpauth://totp/{0}:{1}?secret={2}&issuer={0},&digits=6";

            return string.Format(format, _urlEncoder.Encode("www.bodybody.com"), _urlEncoder.Encode(email), unformattedKey);
        }
    }
}
