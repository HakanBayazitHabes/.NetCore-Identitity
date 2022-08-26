using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace dotNet_Core_Identitity.ViewModels
{
    public class PasswordChangeViewModel
    {
        [Display(Name = "Eski Şifreniz:")]
        [Required(ErrorMessage = "Şifre şfreniz gereklidir.")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Şifreniz en az 4 karakterli olmalıdır.")]
        public string PasswordOld { get; set; }
        [Display(Name = "Yeni Şifreniz:")]
        [Required(ErrorMessage = "Yeni Şifre alanı gereklidir.")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Şifreniz en az 4 karakterli olmalıdır.")]
        public string PasswordNew { get; set; }
        [Display(Name = "Onay Yeni Şifreniz:")]
        [Required(ErrorMessage = "Onay Yeni Şifre  gereklidir.")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Şifreniz en az 4 karakterli olmalıdır.")]
        [Compare("PasswordNew",ErrorMessage ="Yeni şifreniz ve onay şifreniz birbirinden farklıdır"),]
        public string PasswordConfirm { get; set; }
    }
}
