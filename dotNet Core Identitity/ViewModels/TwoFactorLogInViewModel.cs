using dotNet_Core_Identitity.Enums;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace dotNet_Core_Identitity.ViewModels
{
    public class TwoFactorLogInViewModel
    {
        [Display(Name ="Doğrulama Kodunuz")]
        [Required(ErrorMessage ="Doğrulama kodu boş olamaz.")]
        [StringLength(8,ErrorMessage ="Doğrulama kodunuz en fazla 8 habeli olabilir.")]
        public string VerificationCode { get; set; }

        public bool IsRememberMe { get; set; }
        public bool IsRecoverCode { get; set; }
        public TwoFactor TwoFactorType { get; set; }

    }
}
