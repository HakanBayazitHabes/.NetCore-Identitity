﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace dotNet_Core_Identitity.Models
{
    public class AppUser:IdentityUser
    {
        public string City { get; set; }
        public string Picture { get; set; }
        public DateTime? BirthDay { get; set; }
        public int Gender { get; set; }

        public sbyte? TwoFactor { get; set; }
    }
}
