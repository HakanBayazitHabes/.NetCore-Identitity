using dotNet_Core_Identitity.Models;
using dotNet_Core_Identitity.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Mapster;
using Microsoft.AspNetCore.Authorization;

namespace dotNet_Core_Identitity.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminController : BaseController
    {
        public AdminController(UserManager<AppUser> userManager, RoleManager<AppRole> roleManager) : base(userManager, null, roleManager)
        {
        }

        public IActionResult Index()
        {
            return View();
        }
        public IActionResult Claims()
        {
            return View(User.Claims.ToList());
        }
        public IActionResult RoleCreate()
        {
            return View();
        }
        [HttpPost]
        public IActionResult RoleCreate(RoleViewModel roleViewModel)
        {
            AppRole role = new AppRole();

            role.Name = roleViewModel.Name;

            IdentityResult result = roleManager.CreateAsync(role).Result;

            if (result.Succeeded)
            {
                return RedirectToAction("Roles");
            }
            else
            {
                AddModelError(result);
            }

            return View(roleViewModel);
        }
        public IActionResult Roles()
        {
            return View(roleManager.Roles.ToList());
        }
        public IActionResult Users()
        {
            return View(userManager.Users.ToList());
        }

        public IActionResult RoleDelete(string id)
        {
            AppRole role = roleManager.FindByIdAsync(id).Result;
            if (role != null)
            {
                IdentityResult result = roleManager.DeleteAsync(role).Result;
            }
            return RedirectToAction("Roles");
        }

        public IActionResult RoleUpdate(string Id)
        {
            AppRole role = roleManager.FindByIdAsync(Id).Result;
            if (role != null)
            {
                return View(role.Adapt<RoleViewModel>());
            }
            return RedirectToAction("Roles");
        }

        [HttpPost]
        public IActionResult RoleUpdate(RoleViewModel roleViewModel)
        {
            AppRole role = roleManager.FindByIdAsync(roleViewModel.Id).Result;

            if (role != null)
            {
                role.Name = roleViewModel.Name;
                IdentityResult result = roleManager.UpdateAsync(role).Result;

                if (result.Succeeded)
                {
                    return RedirectToAction("Roles");
                }
                else
                {
                    AddModelError(result);
                }
            }
            else
            {
                ModelState.AddModelError("", "Güncelleme işlemi başarısız oldu.");
            }
            return View(roleViewModel);

        }

        public IActionResult RoleAssign(string id)
        {
            TempData["userId"] = id;
            AppUser user = userManager.FindByIdAsync(id).Result;

            ViewBag.userName = user.UserName;

            IQueryable<AppRole> roles = roleManager.Roles;

            List<string> userRoles = userManager.GetRolesAsync(user).Result as List<string>;

            List<RoleAssignViewModel> roleAssignViewModels = new List<RoleAssignViewModel>();

            foreach (var role in roles)
            {
                RoleAssignViewModel roleAssign = new RoleAssignViewModel();
                roleAssign.RoleId = role.Id;
                roleAssign.RoleName = role.Name;

                if (userRoles.Contains(role.Name))
                {
                    roleAssign.Exist = true;
                }
                else
                {
                    roleAssign.Exist = false;
                }
                roleAssignViewModels.Add(roleAssign);
            }
            return View(roleAssignViewModels);
        }
        [HttpPost]
        public async Task<IActionResult> RoleAssign(List<RoleAssignViewModel> roleAssignViewModels)
        {
            AppUser user = userManager.FindByIdAsync(TempData["userId"].ToString()).Result;

            foreach (var item in roleAssignViewModels)
            {
                if (item.Exist)
                {
                    await userManager.AddToRoleAsync(user, item.RoleName);
                }
                else
                {

                    await userManager.RemoveFromRoleAsync(user, item.RoleName);
                }
            }
            return RedirectToAction("Users");
        }

        public async Task<IActionResult> ResetUserPassword(string id)
        {
            AppUser user = await userManager.FindByIdAsync(id);

            PasswordResetByAdminViewModel passwordResetByAdminViewModel = new PasswordResetByAdminViewModel();

            passwordResetByAdminViewModel.UserID = user.Id;

            return View(passwordResetByAdminViewModel);

        }

        [HttpPost]
        public async Task<IActionResult> ResetUserPassword(PasswordResetByAdminViewModel passwordResetByAdminViewModel)
        {
            AppUser user = await userManager.FindByIdAsync(passwordResetByAdminViewModel.UserID);

            string token = await userManager.GeneratePasswordResetTokenAsync(user);

            await userManager.ResetPasswordAsync(user, token, passwordResetByAdminViewModel.NewPassword);

            await userManager.UpdateSecurityStampAsync(user);

            //securityStamp degerini update etmezsem kullanıcı eski şifresiyle sitemizde dolaşmaya devam eder ne zaman çıkış yaparsa o zaman tekrar yeni şifre girmek zorunda 
            //eğer update edersen kullanıcı otomatik olarak sitemize girdiği zaman login ekranına yönlendirilecek

            return RedirectToAction("Users");

        }

    }
}
