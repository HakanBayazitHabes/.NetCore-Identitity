﻿using dotNet_Core_Identitity.Enums;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace dotNet_Core_Identitity.ViewModels
{
    public class AuthenticatorViewModel
    {
        public string SharedKey { get; set; }
        public string AuthenticatorUri { get; set; }
        [Display(Name ="Doğrulama Kodunuz")]
        [Required(ErrorMessage ="Doğrulama kodu gereklidir")]
        public string VerificationCode { get; set; }
        [Display(Name = "İki adımlı kimlik doğrulama tipi")]
        public TwoFactor TwoFactorType { get; set; }
    }
}
