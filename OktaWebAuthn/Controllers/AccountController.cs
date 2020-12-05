using System.Collections.Generic;
using System.Text;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Mvc;
using OktaWebAuthn.Models;

namespace OktaWebAuthn.Controllers
{
    public class AccountController : Controller
    {
        private readonly IFido2 fido2;

        public AccountController(IFido2 fido2)
        {
            this.fido2 = fido2;
        }

        public ActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public ActionResult CredentialOptions([FromBody] RegisterModel model)
        {
            var user = new Fido2User
            {
                DisplayName = $"{model.FirstName} {model.LastName}",
                Name = model.Email,
                Id = Encoding.UTF8.GetBytes(model.Email)
            };

            var options = fido2.RequestNewCredential(user, new List<PublicKeyCredentialDescriptor>());
            return Json(options);
        }
    }
}