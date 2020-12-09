using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Okta.Sdk;
using Okta.Sdk.Configuration;
using OktaWebAuthn.Models;

namespace OktaWebAuthn.Controllers
{
    public class AccountController : Controller
    {
        private readonly IFido2 fido2;
        private OktaClient oktaClient;

        public AccountController(IConfiguration configuration, IFido2 fido2)
        {
            this.fido2 = fido2;

            oktaClient = new OktaClient(new OktaClientConfiguration
            {
                OktaDomain = configuration["Okta:Domain"],
                Token = configuration["Okta:ApiToken"]
            });
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

            HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

            return Json(options);
        }

        [HttpPost]
        public async Task<JsonResult> SaveCredentials([FromBody] AuthenticatorAttestationRawResponse attestationResponse)
        {
            try
            {
                var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
                var options = CredentialCreateOptions.FromJson(jsonOptions);

                var fidoCredentials = await fido2.MakeNewCredentialAsync(attestationResponse, options, IsCredentialUnique);

                var storedCredential = new StoredCredential
                {
                    Descriptor = new PublicKeyCredentialDescriptor(fidoCredentials.Result.CredentialId),
                    PublicKey = fidoCredentials.Result.PublicKey,
                    UserHandle = fidoCredentials.Result.User.Id,
                    SignatureCounter = fidoCredentials.Result.Counter,
                    CredType = fidoCredentials.Result.CredType,
                    RegDate = DateTime.Now,
                    AaGuid = fidoCredentials.Result.Aaguid
                };

                var names = options.User.DisplayName.Split(' ');
                var result = await oktaClient.Users.CreateUserAsync(new CreateUserWithoutCredentialsOptions
                {
                    Profile = new UserProfile
                    {
                        Login = options.User.Name,
                        Email = options.User.Name,
                        DisplayName = options.User.DisplayName,
                        FirstName = names[0],
                        LastName = names[1],
                        ["CredentialId"] = Convert.ToBase64String(fidoCredentials.Result.CredentialId),
                        ["PasswordlessPublicKey"] = JsonConvert.SerializeObject(storedCredential)
                    }
                });

                return Json(fidoCredentials);
            }
            catch (Exception e)
            {
                return Json(new Fido2.CredentialMakeResult { Status = "error", ErrorMessage = e.Message });
            }
        }


        public ActionResult SignIn()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> SignInOptions([FromForm] string username)
        {
            try
            {
                var user = await oktaClient.Users.GetUserAsync(username);

                if (user == null)
                    throw new ArgumentException("Username was not registered");

                var credential = JsonConvert.DeserializeObject<StoredCredential>(user.Profile["PasswordlessPublicKey"].ToString());

                var options = fido2.GetAssertionOptions(new List<PublicKeyCredentialDescriptor> { credential.Descriptor }, UserVerificationRequirement.Discouraged);

                HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

                return Json(options);
            }

            catch (Exception e)
            {
                return Json(new AssertionOptions { Status = "error", ErrorMessage = e.Message });
            }
        }

        [HttpPost]
        public async Task<JsonResult> SignIn([FromBody] AuthenticatorAssertionRawResponse clientResponse)
        {
            try
            {
                var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
                var options = AssertionOptions.FromJson(jsonOptions);

                var user = await GetUserByCredentials(clientResponse.Id);

                var credential = JsonConvert.DeserializeObject<StoredCredential>(user.Profile["PasswordlessPublicKey"].ToString());

                var result = await fido2.MakeAssertionAsync(clientResponse, options, credential.PublicKey, credential.SignatureCounter, 
                                                            args => Task.FromResult(credential.UserHandle.SequenceEqual(args.UserHandle)));

                await UpdateCounter(user, credential, result.Counter);

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Profile.Email)
                };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

                return Json(result);
            }
            catch (Exception e)
            {
                return Json(new AssertionVerificationResult { Status = "error", ErrorMessage = e.Message });
            }
        }

        public async Task<IActionResult> Profile()
        {
            var subject = HttpContext.User.Claims.First(claim => claim.Type == ClaimTypes.Name).Value;

            var user = await oktaClient.Users.GetUserAsync(subject);

            return View(user);
        }

        private async Task<bool> IsCredentialUnique(IsCredentialIdUniqueToUserParams userParams)
        {
            var listUsers = oktaClient.Users.ListUsers(search: $"profile.CredentialId eq \"{Convert.ToBase64String(userParams.CredentialId)}\"");
            var users = await listUsers.CountAsync();
            return users == 0;
        }

        private async Task<IUser> GetUserByCredentials(byte[] credentialId)
        {
            var listUsers = oktaClient.Users.ListUsers(search: $"profile.CredentialId eq \"{Convert.ToBase64String(credentialId)}\"");
            var user = await listUsers.FirstAsync();
            return user;
        }

        private async Task UpdateCounter(IUser user, StoredCredential credential, uint resultCounter)
        {
            credential.SignatureCounter = resultCounter;
            user.Profile["PasswordlessPublicKey"] = JsonConvert.SerializeObject(credential);
            await oktaClient.Users.UpdateUserAsync(user, user.Id, false);
        }
    }
}