using dotNet_Core_Identitity.Enums;
using dotNet_Core_Identitity.Models;
using dotNet_Core_Identitity.Service;
using dotNet_Core_Identitity.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace dotNet_Core_Identitity.Controllers
{
    public class HomeController : BaseController
    {
        private readonly TwoFactorService _twoFactorService;
        private readonly EmailSender _emailSender;
        private readonly SmsSender _smsSender;
        public HomeController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, TwoFactorService twoFactorService, EmailSender emailSender,SmsSender smsSender) : base(userManager, signInManager)
        {
            _twoFactorService = twoFactorService;
            _emailSender = emailSender;
            _smsSender = smsSender;
        }


        public IActionResult Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Member");
            }
            return View();
        }
        public IActionResult LogIn(string ReturnUrl = "/")
        {
            TempData["ReturnUrl"] = ReturnUrl;
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> LogIn(LoginViewModel userlogin)
        {
            if (ModelState.IsValid)
            {
                AppUser user = await userManager.FindByEmailAsync(userlogin.Email);

                if (user != null)
                {
                    if (await userManager.IsLockedOutAsync(user))
                    {
                        ModelState.AddModelError("", "Hesabınız bir süreliğini kilitlenmiştir.Lütfen daha sonra tekrar deneyiniz.");
                        return View(userlogin);
                    }
                    if (!userManager.IsEmailConfirmedAsync(user).Result)
                    {
                        ModelState.AddModelError("", "Email adresiniz onaylanmamıştır.Lütfen epostanızı kontrol ediniz.");
                        return View(userlogin);
                    }
                    bool userCheck = await userManager.CheckPasswordAsync(user, userlogin.Password);

                    if (userCheck)
                    {
                        await userManager.ResetAccessFailedCountAsync(user);
                        await signInManager.SignOutAsync();


                        var result = await signInManager.PasswordSignInAsync(user, userlogin.Password, userlogin.RememberMe, false);//son parametreye true yazarsak bu if'in altındaki else yazmamaıza gerek kalmıyor
                        if (result.RequiresTwoFactor)
                        {
                            if (user.TwoFactor == (int)TwoFactor.Email || user.TwoFactor == (int)(TwoFactor.Phone))
                            {
                                HttpContext.Session.Remove("currentTime");
                            }
                            return RedirectToAction("TwoFactorLogIn", "Home", new { ReturnUrl = TempData["ReturnUrl"].ToString() });
                        }
                        else
                        {
                            return Redirect(TempData["ReturnUrl"].ToString());
                        }
                    }
                    else
                    {
                        await userManager.AccessFailedAsync(user);

                        int fail = await userManager.GetAccessFailedCountAsync(user);
                        ModelState.AddModelError("", $"{fail} kez başarısız giriş");
                        if (fail == 3)
                        {
                            await userManager.SetLockoutEndDateAsync(user, new System.DateTimeOffset(DateTime.Now.AddMinutes(20)));
                            ModelState.AddModelError("", "Hesabınız 3 başarısız girişten dolayı 20 dakika süreyle kilitlenmiştir. Lütfen daha sonra tekrar deneyiniz ");
                        }
                        else
                        {
                            ModelState.AddModelError("", "Email adresiniz veya şifreniz yanlış");
                        }
                    }
                }
                else
                {
                    ModelState.AddModelError("", "Bu email adresine kauıtlı kullanıcı bulunamaıştır.");
                }
            }
            return View(userlogin);
        }
        public async Task<IActionResult> TwoFactorLogIn(string ReturnUrl = "/")
        {
            var user = await signInManager.GetTwoFactorAuthenticationUserAsync();//Giriş yaptığında Identity.TwoFactorUserId adında bir ıd oluşturur bu id'yi kontrol eder ,id'ye ait kullanıcıyı getirir.
            TempData["ReturnUrl"] = ReturnUrl;

            switch ((TwoFactor)user.TwoFactor)
            {
                case TwoFactor.Phone:
                    if (_twoFactorService.TimeLeft(HttpContext)==0)
                    {
                        return RedirectToAction("LogIn");
                    }
                    ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);

                    HttpContext.Session.SetString("codeVerification",_smsSender.Send(user.PhoneNumber));

                    break;
                case TwoFactor.Email:
                    if (_twoFactorService.TimeLeft(HttpContext) == 0)
                    {
                        return RedirectToAction("LogIn");
                    }

                    ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);

                    HttpContext.Session.SetString("codeVerification", _emailSender.Send(user.Email));
                    break;

            }
            return View(new TwoFactorLogInViewModel() { TwoFactorType = (TwoFactor)user.TwoFactor, IsRecoverCode = false, IsRememberMe = false, VerificationCode = string.Empty });
        }
        [HttpPost]
        public async Task<IActionResult> TwoFactorLogIn(TwoFactorLogInViewModel twoFactorLogInViewModel)
        {
            var user = await signInManager.GetTwoFactorAuthenticationUserAsync();//claims'lerdeki ideleriden kullanıcıyı bulur

            ModelState.Clear();
            bool IsSuccessAuth = false;

            if (user.TwoFactor == (int)TwoFactor.MicrosoftGoogle)
            {
                Microsoft.AspNetCore.Identity.SignInResult result;

                if (twoFactorLogInViewModel.IsRecoverCode)
                {
                    result = await signInManager.TwoFactorRecoveryCodeSignInAsync(twoFactorLogInViewModel.VerificationCode);//kurtarma kodları ile giriş
                }
                else
                {
                    result = await signInManager.TwoFactorAuthenticatorSignInAsync(twoFactorLogInViewModel.VerificationCode, twoFactorLogInViewModel.IsRememberMe, false);
                }
                if (result.Succeeded)
                {
                    IsSuccessAuth = true;
                }
                else
                {
                    ModelState.AddModelError("", "Doğrulama Kodu yanlış");
                }
            }
            else if (user.TwoFactor == (int)TwoFactor.Email || user.TwoFactor == (int)TwoFactor.Phone)
            {
                ViewBag.timeLeft = _twoFactorService.TimeLeft(HttpContext);
                if (twoFactorLogInViewModel.VerificationCode == HttpContext.Session.GetString("codeVerification"))
                {
                    await signInManager.SignOutAsync();

                    await signInManager.SignInAsync(user, twoFactorLogInViewModel.IsRememberMe);
                    HttpContext.Session.Remove("currentTime");
                    HttpContext.Session.Remove("codeVerification");
                    IsSuccessAuth = true;
                }
                else
                {
                    ModelState.AddModelError("", "Doğrulama kodu yanlış");
                }
            }

            if (IsSuccessAuth)
            {
                return Redirect(TempData["ReturnUrl"].ToString());
            }
            twoFactorLogInViewModel.TwoFactorType = (TwoFactor)user.TwoFactor;
            return View(twoFactorLogInViewModel);

        }

        public IActionResult SignUp()
        {

            return View();
        }
        [HttpPost]
        public async Task<IActionResult> SignUp(UserViewModel userViewModel)
        {
            if (ModelState.IsValid)
            {

                if (userManager.Users.Any(x => x.PhoneNumber == userViewModel.PhoneNumber))
                {
                    ModelState.AddModelError("", "Bu telefon numarası kayıtlıdır.");
                    return View(userViewModel);
                }

                AppUser user = new AppUser();
                user.UserName = userViewModel.UserName;
                user.Email = userViewModel.Email;
                user.PhoneNumber = userViewModel.PhoneNumber;
                user.TwoFactor = 0;


                IdentityResult result = await userManager.CreateAsync(user, userViewModel.Password);

                if (result.Succeeded)
                {
                    string confirmationToken = await userManager.GenerateEmailConfirmationTokenAsync(user);

                    string link = Url.Action("ConfirmEmail", "Home", new
                    {
                        userId = user.Id,
                        token = confirmationToken
                    }, protocol: HttpContext.Request.Scheme);

                    Helper.EmailConfirmation.SendMail(link, user.Email);

                    return RedirectToAction("LogIn");
                }
                else
                {
                    AddModelError(result);
                }
            }
            return View(userViewModel);
        }

        public IActionResult ResetPassword()
        {
            return View();
        }

        [HttpPost]
        public IActionResult ResetPassword(PasswordResetViewModel passwordResetViewModel)
        {
            AppUser user = userManager.FindByEmailAsync(passwordResetViewModel.Email).Result;

            if (user != null)
            {
                string passwordResetToken = userManager.GeneratePasswordResetTokenAsync(user).Result;

                string passwordResetLink = Url.Action("ResetPasswordConfirm", "Home", new
                {
                    userId = user.Id,
                    token = passwordResetToken
                }, HttpContext.Request.Scheme);
                Helper.PasswordReset.PasswordResetSendEmail(passwordResetLink, user.Email);

                ViewBag.status = "succsess";

            }
            else
            {
                ModelState.AddModelError("", "Sistemde kayıtlı email adresi bulunamamıştır");
            }

            return View(passwordResetViewModel);
        }

        public IActionResult ResetPasswordConfirm(string userId, string token)
        {
            TempData["userId"] = userId;
            TempData["token"] = token;

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ResetPasswordConfirm([Bind("PasswordNew")] PasswordResetViewModel passwordResetViewModel)
        {

            string token = TempData["token"].ToString();
            string userId = TempData["userId"].ToString();

            AppUser user = await userManager.FindByIdAsync(userId);

            if (user != null)
            {
                IdentityResult result = await userManager.ResetPasswordAsync(user, token, passwordResetViewModel.PasswordNew);


                if (result.Succeeded)
                {
                    await userManager.UpdateSecurityStampAsync(user);

                    ViewBag.status = "succsess";
                }
                else
                {
                    AddModelError(result);
                }

            }
            else
            {
                ModelState.AddModelError("", "Beklenmedik bir hata ile karşılaştık , Lütfen daha sonra tekrar deneyiniz ");
            }

            return View(passwordResetViewModel);
        }

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await userManager.FindByIdAsync(userId);

            IdentityResult result = await userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                ViewBag.status = "Email adresiniz onaylanmıştır. Login ekranından giriş yapabilirsiniz";
            }
            else
            {
                ViewBag.status = "Beklenmedik bir hata meydana geldi. Lütfen daha sonra tekrar deneyiniz.";
            }
            return View();

        }

        public IActionResult FacebookLogin(string ReturnUrl)
        {
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl });
            var properties = signInManager.ConfigureExternalAuthenticationProperties("Facebook", RedirectUrl);

            return new ChallengeResult("Facebook", properties);
        }

        public IActionResult GoogleLogin(string ReturnUrl)
        {
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl });
            var properties = signInManager.ConfigureExternalAuthenticationProperties("Google", RedirectUrl);

            return new ChallengeResult("Google", properties);
        }
        public IActionResult MicrosoftLogin(string ReturnUrl)
        {
            string RedirectUrl = Url.Action("ExternalResponse", "Home", new { ReturnUrl = ReturnUrl });
            var properties = signInManager.ConfigureExternalAuthenticationProperties("Microsoft", RedirectUrl);

            return new ChallengeResult("Microsoft", properties);
        }



        public async Task<IActionResult> ExternalResponse(string ReturnUrl = "/")
        {
            ExternalLoginInfo info = await signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction("LogIn");
            }
            else
            {
                Microsoft.AspNetCore.Identity.SignInResult result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);

                if (result.Succeeded)
                {
                    return Redirect(ReturnUrl);
                }
                else
                {
                    AppUser user = new AppUser();

                    user.Email = info.Principal.FindFirst(ClaimTypes.Email).Value;
                    string ExternalUserId = info.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;

                    if (info.Principal.HasClaim(x => x.Type == ClaimTypes.Name))
                    {
                        string userName = info.Principal.FindFirst(ClaimTypes.Name).Value;
                        userName = userName.Replace(' ', '-').ToLower() + ExternalUserId.Substring(0, 5).ToString();
                        user.UserName = userName;
                    }
                    else
                    {
                        user.UserName = info.Principal.FindFirst(ClaimTypes.Email).Value;
                    }

                    AppUser user1 = await userManager.FindByEmailAsync(user.Email);

                    if (user1 == null)
                    {
                        IdentityResult createResult = await userManager.CreateAsync(user);

                        if (createResult.Succeeded)
                        {
                            IdentityResult loginResult = await userManager.AddLoginAsync(user, info);

                            if (loginResult.Succeeded)
                            {
                                //await signInManager.SignInAsync(user, true); normal kullanıcıların gireceği şekilde yazdık böyle yazarsak facebook dan geldiğini anlamayız .cookiesine ulaşamayız
                                await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);
                                return Redirect(ReturnUrl);
                            }
                            else
                            {
                                AddModelError(loginResult);
                            }
                        }
                        else
                        {
                            AddModelError(createResult);
                        }
                    }
                    else
                    {
                        IdentityResult loginResult = await userManager.AddLoginAsync(user1, info);
                        await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true);
                        return Redirect(ReturnUrl);
                    }

                }
            }
            List<string> errors = ModelState.Values.SelectMany(x => x.Errors).Select(y => y.ErrorMessage).ToList();
            return View("Error", errors);
        }

        public ActionResult Error()
        {
            return View();
        }

        public ActionResult Policy()
        {
            return View();
        }

        public JsonResult AgainSendEmail()
        {
            try
            {
                var user = signInManager.GetTwoFactorAuthenticationUserAsync().Result;
                HttpContext.Session.SetString("codeVerification", _emailSender.Send(user.Email));
                return Json(true);

            }
            catch (Exception)
            {

                return Json(false);
            }
        }

    }
}
