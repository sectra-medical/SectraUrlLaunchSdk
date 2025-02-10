using System;
using System.Net;
using System.Web;

namespace Sectra.UrlLaunch.SharedSecret {
    /// <summary>
    /// Main class for managing URL strings used in Sectra's URL launch.
    /// </summary>
    public static class SectraSharedSecretEncryption {

        private const string QueryStringKey = "sharedSecretEncryptedUrlQuery";

        public static bool IsSharedSecretEncryption(string encryptedQueryString) {
            var parsedQueryString = HttpUtility.ParseQueryString(encryptedQueryString);
            var sharedSecretEncryptedUrlQuery = parsedQueryString.Get(QueryStringKey);
            return !string.IsNullOrEmpty(sharedSecretEncryptedUrlQuery);
        }

        public static string Secure(string plainTextQueryString, string base64EncryptionKey) {
            var encryptionKey = Convert.FromBase64String(base64EncryptionKey);
            return Secure(plainTextQueryString, encryptionKey);
        }

        public static string Secure(string plainTextQueryString, byte[] encryptionKey) {
            var encryptedString = EncryptedOneTimeSignature.EncryptAndSign(plainTextQueryString, encryptionKey);
            return $"{QueryStringKey}={WebUtility.UrlEncode(encryptedString)}";
        }

        public static string View(string encryptedQueryString, string base64EncryptionKey) {
            var encryptionKey = Convert.FromBase64String(base64EncryptionKey);
            return View(encryptedQueryString, encryptionKey);
        }

        public static string View(string encryptedQueryString, byte[] encryptionKey) {
            var parsedQueryString = HttpUtility.ParseQueryString(encryptedQueryString);
            var sharedSecretEncryptedUrlQuery = parsedQueryString.Get(QueryStringKey);
            if (string.IsNullOrEmpty(sharedSecretEncryptedUrlQuery)) {
                throw new Exception($"The provided '{QueryStringKey}' value either does not exist or is not set.");
            }

            return EncryptedOneTimeSignature.VerifyAndDecrypt(sharedSecretEncryptedUrlQuery, encryptionKey);
        }
    }
}
