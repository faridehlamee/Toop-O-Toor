using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Web;
using volleyballMVC.ViewModels;

namespace volleyballMVC.BusinessLogic
{
    public class MailHelper
    {
        public const string SUCCESS = "A confirmation email has been sent. Please check your email!";
        public const string FAILURE = "Failure sending mail.";

        //const string TO = "hassanhosseinpoor@yahoo.com"; // Specify where you want this email sent.
        // This value may/may not be constant.
        // To get started use one of your email 
        // addresses.
        public string EmailFromArvixe(RegisteredUser registeredUser,string confirmRegistration)
        {   

            // Use credentials of the Mail account that you created with the steps above.
            const string FROM = "Hassan1@h-hosseinpour.com";
            const string FROM_PWD = "tv20021809";
            const bool USE_HTML = true;
            string TO = registeredUser.Email;

            // Get the mail server obtained in the steps described above.
            const string SMTP_SERVER = "143.95.249.35";
            try
            {
                MailMessage mailMsg = new MailMessage(FROM, TO);
                mailMsg.Subject = "Confirmation Email for " + registeredUser.UserName;
                mailMsg.Body = confirmRegistration + "<br/>Sent by: ToopOToor Inc" ;
                mailMsg.IsBodyHtml = USE_HTML;

                SmtpClient smtp = new SmtpClient();
                smtp.Port = 25;
                smtp.Host = SMTP_SERVER;
                smtp.Credentials = new System.Net.NetworkCredential(FROM, FROM_PWD);
                smtp.Send(mailMsg);
            }
            catch//(System.Exception ex)
            {
                //return ex.Message;
                return FAILURE;
            }
            return SUCCESS;
        }

    }
}