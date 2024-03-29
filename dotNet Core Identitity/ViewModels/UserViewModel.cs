﻿using dotNet_Core_Identitity.Enums;
using dotNet_Core_Identitity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace dotNet_Core_Identitity.ViewModels
{
    public class UserViewModel
    {
        [Required(ErrorMessage = "Kullanıcı ismi gereklidir.")]
        [Display(Name = "Kullanıcı Adı:")]
        public string UserName { get; set; }

        [Display(Name = "Tel No:")]
        [RegularExpression(@"^(0(\d{3}) (\d{3}) (\d{2}) (\d{2}))$", ErrorMessage = "Telefon numarası uygun formatta değil.")]
        public string PhoneNumber { get; set; }

        [Required(ErrorMessage = "Email Adresi Gereklidir.")]
        [Display(Name = "Email Adresi:")]
        [EmailAddress(ErrorMessage = "Email Adresiniz doğru formatta değil")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Şifreniz gereklidir.")]
        [Display(Name = "Şifre:")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "Doğum Tarihi:")]
        [DataType(DataType.Date)]
        public DateTime? BirthDay { get; set; }
        public string Picture { get; set; }
        [Display(Name = "Şehir:")]
        public string City { get; set; }
        [Display(Name = "Cinsiyet:")]
        public Gender Gender { get; set; }

    }
}
