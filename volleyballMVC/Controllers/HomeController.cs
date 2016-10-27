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

namespace volleyballMVC.Controllers
{
    public class HomeController : Controller
    {
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
                if (identityUser != null)
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
            ViewBag.errorLogin = "Oops! You have entered invalid credentials. Please try again! ";
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
            var manager = new UserManager<IdentityUser>(userStore);
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
                    var authenticationManager
                                      = HttpContext.Request.GetOwinContext().Authentication;
                    var userIdentity = manager.CreateIdentity(identityUser,
                                               DefaultAuthenticationTypes.ApplicationCookie);
                    authenticationManager.SignIn(new AuthenticationProperties() { },
                                                 userIdentity);
                }
            }
           
            ViewBag.Register = "Resister";
            return RedirectToAction("SecureArea");
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
    }
}

