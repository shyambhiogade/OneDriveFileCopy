using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace MSLoginTest.Models
{

    public class OAuth2RequestManager
    {
        private static ReaderWriterLockSlim SessionLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);

        /// Generate a state value using a random Guid value, the origin of the request and the scopes being requested.
        /// The state value will be consumed by the OAuth controller for validation, for specifying the corresc scopes during code redemption, and redirection after code redemption.
        /// Here we store the random Guid in the session for validation by the OAuth controller.
        private static string GenerateState(string requestUrl, HttpContextBase httpcontext, UrlHelper url, string[] scopes)
        {
            try
            {
                string stateGuid = Guid.NewGuid().ToString();
                SaveUserStateValue(stateGuid, httpcontext);

                List<String> stateList = new List<String>();
                stateList.Add(stateGuid);
                stateList.Add(requestUrl);

                // turn the scopes array into a comma separated list string
                string scopeslist = scopes[0];
                if (scopes.Count() > 1)
                    for (int i = 1; i < scopes.Count(); i++)
                    {
                        scopeslist += "," + scopes[i];
                    }
                stateList.Add(scopeslist);

                var formatter = new BinaryFormatter();
                var stream = new MemoryStream();
                formatter.Serialize(stream, stateList);
                var stateBits = stream.ToArray();

                return url.Encode(Convert.ToBase64String(stateBits));
            }
            catch
            {
                return null;
            }
        }
        // save the state in the session for the current user
        private static void SaveUserStateValue(string stateGuid, HttpContextBase httpcontext)
        {
            string signedInUserID = ClaimsPrincipal.Current.FindFirst(System.IdentityModel.Claims.ClaimTypes.NameIdentifier).Value;
            SessionLock.EnterWriteLock();
            httpcontext.Session[signedInUserID + "_state"] = stateGuid;
            SessionLock.ExitWriteLock();
        }
        private static string ReadUserStateValue(HttpContextBase httpcontext)
        {
            string signedInUserID = ClaimsPrincipal.Current.FindFirst(System.IdentityModel.Claims.ClaimTypes.NameIdentifier).Value;
            string stateGuid = string.Empty;
            SessionLock.EnterReadLock();
            stateGuid = (string)httpcontext.Session[signedInUserID + "_state"];
            SessionLock.ExitReadLock();
            return stateGuid;
        }
        // Verify that the state identifier in the state string corresponds to the GUID saved in the session for the current user
        // If the check succeeds, return the scopes to request when redeeming the code and the URL to which the app will be redirected after redemption
        public static CodeRedeptionData ValidateState(string state, HttpContextBase httpcontext)
        {
            try
            {
                var stateBits = Convert.FromBase64String(state);
                var formatter = new BinaryFormatter();
                var stream = new MemoryStream(stateBits);
                List<String> stateList = (List<String>)formatter.Deserialize(stream);
                var stateGuid = stateList[0];
                //TODO - cleaning up should not be necessary, I have just one entry per user
                // but at least I should do it for making the state single use                
                if (stateGuid == ReadUserStateValue(httpcontext))
                {
                    string returnURL = stateList[1];
                    string[] scopes = stateList[2].Split(',');
                    return new CodeRedeptionData()
                    {
                        RequestOriginatorUrl = returnURL,
                        Scopes = scopes
                    };
                }
                else
                    return null;
            }
            catch
            {
                return null;
            }
        }

        public static async Task<string> GenerateAuthorizationRequestUrl(string[] scopes, ConfidentialClientApplication cca, HttpContextBase httpcontext, UrlHelper url)
        {
            string signedInUserID = ClaimsPrincipal.Current.FindFirst(System.IdentityModel.Claims.ClaimTypes.NameIdentifier).Value;
            string preferredUsername = ClaimsPrincipal.Current.FindFirst("preferred_username").Value;
            Uri oauthCodeProcessingPath = new Uri(httpcontext.Request.Url.GetLeftPart(UriPartial.Authority).ToString()+ "/default/callback/");
            string state = GenerateState(httpcontext.Request.Url.ToString(), httpcontext, url, scopes);
            string tenantID = ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value;
            string domain_hint = (tenantID == "9188040d-6c67-4c5b-b112-36a304b66dad") ? "consumers" : "organizations";
            Uri authzMessageUri = await cca.GetAuthorizationRequestUrlAsync(scopes,
                oauthCodeProcessingPath.ToString(),
                preferredUsername,
                state == null ? null : "&state=" + state + "&domain_hint=" + domain_hint,
                null,
                cca.Authority,
                null);
            return authzMessageUri.ToString();

        }
    }

    public class CodeRedeptionData
    {
        public string RequestOriginatorUrl { get; set; }
        public string[] Scopes { get; set; }
    }

    public class MSALSessionCache : TokenCache
    {
        private static ReaderWriterLockSlim SessionLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);
        string UserId = string.Empty;
        string CacheId = string.Empty;
        HttpContextBase httpContext = null;

        public MSALSessionCache(string userId, HttpContextBase httpcontext)
        {
            // not object, we want the SUB
            UserId = userId;
            CacheId = UserId + "_TokenCache";
            httpContext = httpcontext;
            this.AfterAccess = AfterAccessNotification;
            this.BeforeAccess = BeforeAccessNotification;
            Load();
        }

        public void SaveUserStateValue(string state)
        {
            SessionLock.EnterWriteLock();
            httpContext.Session[CacheId+"_state"] = state;
            SessionLock.ExitWriteLock();
        }
        public string ReadUserStateValue()
        {
            string state = string.Empty;
            SessionLock.EnterReadLock();
            //this.Deserialize((byte[])HttpContext.Current.Session[CacheId]);
            state = (string) httpContext.Session[CacheId + "_state"];
            SessionLock.ExitReadLock();
            return state;
        }
        public void Load()
        {
            SessionLock.EnterReadLock();
            //this.Deserialize((byte[])HttpContext.Current.Session[CacheId]);
            this.Deserialize((byte[])httpContext.Session[CacheId]);
            SessionLock.ExitReadLock();
        }

        public void Persist()
        {
            SessionLock.EnterWriteLock();

            // Optimistically set HasStateChanged to false. We need to do it early to avoid losing changes made by a concurrent thread.
            this.HasStateChanged = false;

            // Reflect changes in the persistent store
            httpContext.Session[CacheId] = this.Serialize();
            SessionLock.ExitWriteLock();
        }

        // Empties the persistent store.
        public override void Clear(string cliendId)
        {
            base.Clear(cliendId);
            httpContext.Session.Remove(CacheId);
        }

        // Triggered right before ADAL needs to access the cache.
        // Reload the cache from the persistent store in case it changed since the last access.
        void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            Load();
        }

        // Triggered right after ADAL accessed the cache.
        void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // if the access operation resulted in a cache update
            if (this.HasStateChanged)
            {
                Persist();
            }
        }
    }
}
