﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace dotNet_Core_Identitity.Service
{
    public class TwoFactorOptions
    {
        public string SendGrid_ApiKey { get; set; }
        public int CodeTimeExpire { get; set; }
    }
}
