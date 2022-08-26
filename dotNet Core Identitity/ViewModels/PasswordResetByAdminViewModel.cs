using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace dotNet_Core_Identitity.ViewModels
{
    public class PasswordResetByAdminViewModel
    {
        public string UserID { get; set; }
        [Display(Name ="Yeni Şifre")]
        public string NewPassword { get; set; }
    }
}
