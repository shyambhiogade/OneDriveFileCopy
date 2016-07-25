using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using System.Configuration;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Globalization;
using System.IdentityModel.Tokens;
using Microsoft.Identity.Client;
using MSLoginTest.Models;
using System.IdentityModel.Claims;
using System.Web;
using System.Diagnostics;
using System.Security.Claims;

namespace MSLoginTest
{
    public partial class Startup
    {
        public static string clientId = "5484ce6a-b695-47c2-b975-2bd540e3f398";
        public static string appKey = "EZotv57Bmc5jPBW5cfABvXT";
        public static string aadInstance = "https://login.microsoftonline.com/{0}{1}";
        public static string redirectUri = "http://localhost:39831/Default/callback/";
        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    // The `Authority` represents the v2.0 endpoint - https://login.microsoftonline.com/common/v2.0
                    // The `Scope` describes the initial permissions that your app will need.  See https://azure.microsoft.com/documentation/articles/active-directory-v2-scopes/                    
                    ClientId = clientId,
                    Authority = String.Format(CultureInfo.InvariantCulture, aadInstance, "common", "/v2.0"),                    
                    //Scope = "openid email profile offline_access Mail.Read Mail.Send https://graph.microsoft.com/Files.ReadWrite",
                    Scope = "openid email profile offline_access https://graph.microsoft.com/Files.ReadWrite",                    
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        // If there is a code in the OpenID Connect response, redeem it for an access token and refresh token, and store those away.
                        AuthorizationCodeReceived = async (context) =>
                            {
                                var code = context.Code;
                                string signedInUserID = context.AuthenticationTicket.Identity.FindFirst(System.IdentityModel.Claims.ClaimTypes.NameIdentifier).Value;

                                //ConfidentialClientApplication cca = new ConfidentialClientApplication(clientId, redirectUri,
                                //       new ClientCredential(appKey),
                                //       new MSALSessionCache(signedInUserID, context.OwinContext.Environment["System.Web.HttpContextBase"] as HttpContextBase));

                                ConfidentialClientApplication cca = new ConfidentialClientApplication(clientId, context.OwinContext.Request.Uri.OriginalString,
                                       new ClientCredential(appKey),
                                       new TokenCache());

                                string[] scopes = { "" };
                                AuthenticationResult result;
                                try
                                {
                                    result = await cca.AcquireTokenByAuthorizationCodeAsync(scopes, code);

                                    ClaimsIdentity claimsId = context.AuthenticationTicket.Identity;
                                    var accessTokenClaimKey = "http://schemas.exceladdins.com/identity/claims/access_token";
                                    claimsId.AddClaim(new System.Security.Claims.Claim(accessTokenClaimKey, result.Token));

                                    var identity = context.OwinContext.Authentication.User.Identity as ClaimsIdentity;
                                    var existingClaim = identity.FindFirst(accessTokenClaimKey);
                                    if (existingClaim != null)
                                    {
                                        identity.RemoveClaim(existingClaim);
                                    }
                                    identity.AddClaim(new System.Security.Claims.Claim(accessTokenClaimKey, result.Token));


                                    Debug.WriteLine(result.Token);
                                }                                
                                catch (Exception eee)
                                {
                                    Debug.WriteLine(eee.ToString());
                                    context.Response.Redirect("/default/error");
                                }
                            },
                        RedirectToIdentityProvider = (context) =>
                        {
                            // This ensures that the address used for sign in and sign out is picked up dynamically from the request
                            // this allows you to deploy your app (to Azure Web Sites, for example)without having to change settings
                            // Remember that the base URL of the address used here must be provisioned in Azure AD beforehand.

                            string appBaseUrl = context.Request.Scheme + "://" + context.Request.Host + context.Request.PathBase + "";
                            string redirctUrl1 = "";
                            if (context.Request.Query.Get("id") == "1")
                            {
                                redirctUrl1 = appBaseUrl + "/Default/callback/";
                            }
                            else
                            {
                                redirctUrl1 = appBaseUrl + "/Default/callback1/";
                            }

                            //redirctUrl1 = appBaseUrl + "/Default/callback/";

                            context.ProtocolMessage.RedirectUri = redirctUrl1;

                            return Task.FromResult(0);
                        },
                        AuthenticationFailed = (notification) =>
                        {
                            notification.HandleResponse();
                            notification.Response.Redirect("/Error?message=" + notification.Exception.Message);
                            return Task.FromResult(0);
                        }
                    }
                });
        }
    }

}
