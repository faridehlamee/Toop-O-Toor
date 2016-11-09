using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using volleyballMVC.ViewModels;
using volleyballMVC.BusinessLogic;

namespace volleyballMVC.Controllers
{
    public class HomeController : Controller
    {

        const string EMAIL_CONFIRMATION = "EmailConfirmation";
        const string PASSWORD_RESET = "ResetPassword";

        void CreateTokenProvider(UserManager<IdentityUser> manager, string tokenType)
        {
            manager.UserTokenProvider = new EmailTokenProvider<IdentityUser>();
        }
        [HttpGet]
        public ActionResult Index()
        {
            return View();
        }
        [HttpGet]
        public ActionResult Login()
        {
            ViewBag.Login = "Login";
            return View();
        }
        [HttpPost]
        public ActionResult Login(Login login)
        {
            ViewBag.errorLogin = "";
            // UserStore and UserManager manages data retreival.
            UserStore<IdentityUser> userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
            IdentityUser identityUser = manager.Find(login.UserName,
                                                             login.Password);

            if (ModelState.IsValid)
            {
                if(ValidLogin(login))
                    {
                    IAuthenticationManager authenticationManager
                                           = HttpContext.GetOwinContext().Authentication;
                    authenticationManager
                   .SignOut(DefaultAuthenticationTypes.ExternalCookie);

                    var identity = new ClaimsIdentity(new[] {
                                            new Claim(ClaimTypes.Name, login.UserName),
                                        },
                                        DefaultAuthenticationTypes.ApplicationCookie,
                                        ClaimTypes.Name, ClaimTypes.Role);
                    // SignIn() accepts ClaimsIdentity and issues logged in cookie. 
                    authenticationManager.SignIn(new AuthenticationProperties
                    {
                        IsPersistent = false
                    }, identity);
                    return RedirectToAction("SecureArea", "Home");
                }
            }
            //TempData["MaxFailedAccess"] = manager.MaxFailedAccessAttemptsBeforeLockout;
          //  ViewBag.errorLogin = "Oops! You have entered invalid credentials. Please try again! ";
            return View();
        }
        [HttpGet]
        public ActionResult Register()
        {
            ViewBag.Register = "Resister";
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisteredUser newUser)
        {
            ViewBag.Register = "";
            var userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore)
            {
                UserLockoutEnabledByDefault = true,
                DefaultAccountLockoutTimeSpan = new TimeSpan(0, 2, 0),
                MaxFailedAccessAttemptsBeforeLockout = 3
            };

            var identityUser = new IdentityUser()
            {
                UserName = newUser.UserName,
                Email = newUser.Email
            };
            //this query finds if there is a another user with this userName or no
            var user = manager.Users.FirstOrDefault(u => u.UserName == newUser.UserName);
           
            if (user != null)
            {
                ViewBag.ExistedUser = "This user name is already existed! Try another user name.";
                return View();
                
            }
            else
            {
                IdentityResult result = manager.Create(identityUser, newUser.Password);

                if (result.Succeeded)
                {
                    CreateTokenProvider(manager, EMAIL_CONFIRMATION);

                    var code = manager.GenerateEmailConfirmationToken(identityUser.Id);
                    var callbackUrl = Url.Action("ConfirmEmail", "Home",
                                                   new { userId = identityUser.Id, code = code },
                                                       protocol: Request.Url.Scheme);

                    string confirmRegistration = "Please confirm your account by clicking this link: <a href=\""
                                    + callbackUrl + "\">Confirm Registration</a>";

                    MailHelper mailer = new MailHelper();
                    string response = mailer.EmailFromArvixe(newUser, confirmRegistration);

                    if (response != "Failure sending mail.")
                    {
                        ViewBag.Success = response;
                    }
                    else
                    {
                        ViewBag.Failure = response;
                    }

                }
            }
            
            ViewBag.Register = "Resister";
            return View();
        }
        [Authorize]
        public ActionResult SecureArea()
        {
            ViewBag.display = "inline";
            return View();
        }

        public ActionResult Logout()
        {
            var ctx = Request.GetOwinContext();
            var authenticationManager = ctx.Authentication;
            authenticationManager.SignOut();
            return RedirectToAction("Index", "Home");
        }

        bool ValidLogin(Login login)
        {
            UserStore<IdentityUser> userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> userManager = new UserManager<IdentityUser>(userStore)
            {
                UserLockoutEnabledByDefault = true,
                DefaultAccountLockoutTimeSpan = new TimeSpan(0, 2, 0),
                MaxFailedAccessAttemptsBeforeLockout = 3
            };
            var user = userManager.FindByName(login.UserName);

            if (user == null)
            {
                ViewBag.errorLogin = "Oops! You have entered invalid credentials. Please try again! ";
                return false;
            }
               

            // User is locked out.
            if (userManager.SupportsUserLockout && userManager.IsLockedOut(user.Id))
            {
                ViewBag.errorLogin = "Oops!You are locked. you can not login up to 2 minutes! ";
                return false;

            }


            // Validated user was locked out but now can be reset.
            if (userManager.CheckPassword(user, login.Password)
                                            && userManager.IsEmailConfirmed(user.Id))
            {
                if (userManager.SupportsUserLockout
                 && userManager.GetAccessFailedCount(user.Id) > 0)
                {
                    userManager.ResetAccessFailedCount(user.Id);
                }
            }
            // Login is invalid so increment failed attempts.
            else {
                bool lockoutEnabled = userManager.GetLockoutEnabled(user.Id);
                if (userManager.SupportsUserLockout && userManager.GetLockoutEnabled(user.Id))
                {
                 userManager.AccessFailed(user.Id);
                    //this number shows the number of failed login
                    //int i = userManager.GetAccessFailedCount(user.Id);
                    //if(i == 3)
                    //{
                    //    ViewBag.Timeout = "you can not login up to 10 minutes later!";

                    //}
                    ViewBag.errorLogin = "Oops! GetAccessFailedCount. Please try again! ";
                    return false;
                }
            }
            return true;
        }

        public ActionResult ConfirmEmail(string userID, string code)
        {
            var userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
            var user = manager.FindById(userID);
            CreateTokenProvider(manager, EMAIL_CONFIRMATION);
            try
            {
                IdentityResult result = manager.ConfirmEmail(userID, code);
                if (result.Succeeded)
                    ViewBag.Message = "You are now registered!";
            }
            catch
            {
                ViewBag.Message = "Validation attempt failed!";
            }
            return View();
        }

        [HttpGet]
        public ActionResult ForgotPassword()
        {
            return View();
        }
        [HttpPost]
        public ActionResult ForgotPassword(string email)
        {
            var userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
            var user = manager.FindByEmail(email);
            CreateTokenProvider(manager, PASSWORD_RESET);

            var code = manager.GeneratePasswordResetToken(user.Id);
            var callbackUrl = Url.Action("ResetPassword", "Home",
                                         new { userId = user.Id, code = code},
                                         protocol: Request.Url.Scheme);
            ViewBag.FakeEmailMessage = "Please reset your password by clicking <a href=\""
                                     + callbackUrl + "\">here</a>";
            return View();
        }

        [HttpGet]
        public ActionResult ResetPassword(string userID, string code)
        {
            ViewBag.PasswordToken = code;
            ViewBag.UserID = userID;
            return View();
        }
        [HttpPost]
        public ActionResult ResetPassword(string password, string passwordConfirm,
                                          string passwordToken, string userID)
        {

            var userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> manager = new UserManager<IdentityUser>(userStore);
            var user = manager.FindById(userID);
            CreateTokenProvider(manager, PASSWORD_RESET);

            IdentityResult result = manager.ResetPassword(userID, passwordToken, password);
            if (result.Succeeded)
                ViewBag.Result = "The password has been reset.";
            else
                ViewBag.Result = "The password has not been reset.";
            return View();
        }


    }
}

