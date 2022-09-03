using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace dotNet_Core_Identitity.Service
{
    public class SmsSender
    {
        private readonly TwoFactorOptions _twoFactorOptions;
        private readonly TwoFactorService _twoFactorService;

        public SmsSender(IOptions<TwoFactorOptions> options, TwoFactorService twoFactorService)//IOptions appsettings.json dosyasına erişir
        {
            _twoFactorOptions = options.Value;
            _twoFactorService = twoFactorService;
        }

        public string Send(string phone)
        {
            string code = _twoFactorService.GetCodeVerification().ToString();

            // SMS PROVIDER CODE
        //Webconfig file:
        //< configuration >
        //< appSettings >
        //< add key = "TwilioAccountSid" value = "PutAccountSidHere" />


        //< add key = "TwilioAuthToken" value = "PutValueHere" />


        //< add key = "MyPhoneNumber" value = "+PutNumberHere" />
            
            //return code;
            return "2222";
        }


    }
}
