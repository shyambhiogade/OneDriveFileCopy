using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Identity.Client;
using System.IdentityModel.Claims;
using MSLoginTest.Models;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Net.Http;
using System.Net.Http.Headers;
using System.IO;
using System.Web.Script.Serialization;
using System.Text;

namespace MSLoginTest.Controllers
{
    public class DefaultController : Controller
    {
        // GET: Default
        public ActionResult Index(int id)
        {
            if (id == 1)
            {
                HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/Default/callback/" },
                    OpenIdConnectAuthenticationDefaults.AuthenticationType);

            }
            else
            {
                HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/Default/callback1/" },
    OpenIdConnectAuthenticationDefaults.AuthenticationType);

            }
            return new EmptyResult();
        }

        public async Task<ActionResult> callback()
        {

            string accessTokenClaimType = "http://schemas.exceladdins.com/identity/claims/access_token";
            var access_token = ClaimsPrincipal.Current.FindFirst(accessTokenClaimType).Value;
            if (access_token == null)
            {
                ViewBag.AuthorizationRequest = "Error retrieving token";
            }
            else
            {
                ViewBag.AuthorizationRequest = access_token;
            }

            await exportExcelToUsersOneDrive(access_token);

            return Redirect(ViewBag.FileName);
        }

        public async Task<ActionResult> callback1()
        {

            string accessTokenClaimType = "http://schemas.exceladdins.com/identity/claims/access_token";
            var access_token = ClaimsPrincipal.Current.FindFirst(accessTokenClaimType).Value;
            if (access_token == null)
            {
                ViewBag.AuthorizationRequest = "Error retrieving token";
            }
            else
            {
                ViewBag.AuthorizationRequest = access_token;
            }

            await exportExcelToUsersOneDrive(access_token);

            return Redirect(ViewBag.FileName);
        }

        #region Private Functions 

        private string getExcelFileName()
        {
            DateTime dt = DateTime.Now;
            string fileName = "WonderwareInsightExcel_" + dt.Year.ToString() + dt.Month.ToString() + dt.Day.ToString() + dt.Hour.ToString() +
                dt.Minute.ToString() + dt.Second.ToString() + dt.Millisecond.ToString() + ".xlsx";
            return fileName;
        }

        private async Task exportExcelToUsersOneDrive(string accesstoken)
        {
            string excelFile = getExcelFileName();
            // check if same excel name is present, if yes, change the name and try again.
            bool excelExist = true; int maxAttempt = 5;
            while (excelExist && maxAttempt > 0)
            {
                maxAttempt--;
                excelFile = getExcelFileName();
                excelExist = await checkExcelPresent(accesstoken, excelFile);
            }
            // check if folder present, if yes get its id, if not create it and get its id.
            string folderId = await getAddInFolderId(accesstoken);

            if (string.IsNullOrWhiteSpace(folderId) == true)
            {
                folderId = await createAddInFolder(accesstoken);
            }

            if (string.IsNullOrWhiteSpace(folderId) == false)
            {
                var excelFilePath = await postExcelUsingWebClient(accesstoken, folderId, excelFile);

                ViewBag.oneDriveExcelFile = excelFilePath;
            }
        }

        private async Task<bool> checkExcelPresent(string accessToken, string excelfile)
        {
            var excelEndPoints = "https://graph.microsoft.com/v1.0/me/drive/root:/InfoClientAddIn/" + excelfile;

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                using (HttpResponseMessage response = await client.GetAsync(excelEndPoints))
                {
                    if (response.IsSuccessStatusCode)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
            }
        }

        private async Task<string> getAddInFolderId(string accessToken)
        {
            var infoClientAddInEndPoints = "https://graph.microsoft.com/v1.0/me/drive/root:/InfoClientAddIn";

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                using (HttpResponseMessage response = await client.GetAsync(infoClientAddInEndPoints))
                {
                    string returnValue = "";
                    if (response.IsSuccessStatusCode)
                    {
                        var data = await response.Content.ReadAsStringAsync();
                        JavaScriptSerializer serilaizer = new JavaScriptSerializer();
                        object d = serilaizer.Deserialize<object>(data);

                        if (d is Dictionary<string, object>)
                        {
                            var dict = d as Dictionary<string, object>;
                            foreach (var item in dict)
                            {
                                if (item.Key == "id")
                                {
                                    returnValue = item.Value as string;
                                    break;
                                }
                            }
                        }
                    }
                    return returnValue;
                }
            }
        }

        private async Task<string> createAddInFolder(string accessToken)
        {
            var childrenEndPoints = "https://graph.microsoft.com/v1.0/me/drive/root/children";

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                var requestData = "{name: 'InfoClientAddIn',folder: { }}";
                var ss = new StringContent(requestData, Encoding.UTF8, "application/json");
                using (HttpResponseMessage response = await client.PostAsync(childrenEndPoints, ss))
                {
                    string returnValue = "";
                    if (response.IsSuccessStatusCode)
                    {
                        var data = await response.Content.ReadAsStringAsync();
                        JavaScriptSerializer serilaizer = new JavaScriptSerializer();
                        object d = serilaizer.Deserialize<object>(data);

                        if (d is Dictionary<string, object>)
                        {
                            var dict = d as Dictionary<string, object>;
                            foreach (var item in dict)
                            {
                                if (item.Key == "id")
                                {
                                    returnValue = item.Value as string;
                                    break;
                                }
                            }
                        }
                    }
                    else
                    {
                        ViewBag.ErrorMsg = response.ReasonPhrase;
                    }
                    return returnValue;
                }
            }
        }

        private async Task<string> postExcelUsingWebClient(string accessToken, string folderId, string excelFileName)
        {
            string excelFileEndPoint = "https://graph.microsoft.com/v1.0/me/drive/items/" + folderId + "/children/" + excelFileName + "/content";

            DirectoryInfo dir = new DirectoryInfo(Server.MapPath(@"~/ExcelTemplate/ExcelTemplate.xlsx"));

            using (var stream = System.IO.File.OpenRead(dir.FullName))
            {
                using (var client = new HttpClient())
                {
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                    using (HttpResponseMessage response = await client.PutAsync(excelFileEndPoint, new StreamContent(stream)))
                    {
                        string returnValue = "";
                        if (response.IsSuccessStatusCode)
                        {
                            var data = await response.Content.ReadAsStringAsync();
                            JavaScriptSerializer serilaizer = new JavaScriptSerializer();
                            object d = serilaizer.Deserialize<object>(data);

                            if (d is Dictionary<string, object>)
                            {
                                var dict = d as Dictionary<string, object>;
                                string etagValue = "", webUrlValue = "";
                                foreach (var item in dict)
                                {
                                    if (item.Key == "eTag")
                                    {
                                        string value = item.Value as string;
                                        int index1 = value.IndexOf("{"); int index2 = value.IndexOf('}');
                                        if (index1 > 0 && index2 > 0)
                                        {
                                            etagValue = value.Substring(index1, index2);
                                        }
                                    }
                                    if (item.Key == "webUrl")
                                    {
                                        returnValue = item.Value as string;
                                        string value = item.Value as string;
                                        int index1 = value.IndexOf("/Documents/InfoClientAddIn/" + excelFileName);
                                        if (index1 > 0)
                                        {
                                            webUrlValue = value.Substring(0, index1);
                                        }
                                    }
                                }

                                if (!string.IsNullOrEmpty(webUrlValue) && !string.IsNullOrEmpty(etagValue))
                                {
                                    returnValue = webUrlValue + "/_layouts/15/WopiFrame.aspx?sourcedoc=" + etagValue + "&file=" + excelFileName +
                                        "&action=default";
                                }
                            }
                        }
                        else
                        {
                            ViewBag.ErrorMsg = response.ReasonPhrase;
                        }
                        ViewBag.FileName = returnValue;
                        return returnValue;
                    }
                }
            }
        }

        #endregion Private Functions

        public ActionResult error()
        {
            return new EmptyResult();
        }
    }
}