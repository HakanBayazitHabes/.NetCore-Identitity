﻿using dotNet_Core_Identitity.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace dotNet_Core_Identitity.ClaimProvider
{
    public class ClaimProvider : IClaimsTransformation
    {
        public UserManager<AppUser> userManager { get; set; }

        public ClaimProvider(UserManager<AppUser> userManager)
        {
            this.userManager = userManager;
        }

        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            if (principal != null && principal.Identity.IsAuthenticated)
            {
                ClaimsIdentity identity = principal.Identity as ClaimsIdentity;
                AppUser user = await userManager.FindByNameAsync(identity.Name);

                if (user != null)
                {
                    if (user.BirthDay != null)
                    {
                        var today = DateTime.Today;
                        var age = today.Year - user.BirthDay?.Year;

                        if (age > 15)
                        {
                            Claim ViolenceClaim = new Claim("violence", true.ToString(), ClaimValueTypes.String, "Internal");
                            identity.AddClaim(ViolenceClaim);
                        }
                    }

                    if (user.City != null)
                    {
                        if (!principal.HasClaim(x => x.Type == "city"))
                        {
                            Claim CityClaim = new Claim("city", user.City, ClaimValueTypes.String, "Internal");
                            identity.AddClaim(CityClaim);
                        }
                    }
                }
            }
            return principal;
        }
    }
}
