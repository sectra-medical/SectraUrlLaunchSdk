/** Simple URL Launch example
 * 
 * Minimal example on how to launch UniView using single sign-on with the
 * Shared Secret encryption method.
 * 
 */

using Sectra.UrlLaunch.SharedSecret;
using Sectra.UrlLaunch.UrlAccessString;
using System.Diagnostics;

// Use the same key as in the UrlLaunchExample.WebApi example
var base64Key = "EpNnJ5vPSEL5vqSgG7Oe8fzgICZ3pzcqn1bEoHqzDA8=";
var key = Convert.FromBase64String(base64Key);

// Create a plain text query string
var parameters = new Parameters {
    UserId = "MyUserName",
};
var plainTextQueryString = QueryString.GetQueryString(parameters);

// Create an encrypted launch string using the Shared Secret encryption algorithm
var encryptedQueryString = SectraSharedSecretEncryption.Secure(plainTextQueryString, key);
var launchString = $"http://localhost:5079/UrlLaunchExampleApi/?{encryptedQueryString}";

// Open UrlLaunchExample.WebApi URL in default browser
var startInfo = new ProcessStartInfo(launchString) {
    UseShellExecute = true,
};
Process.Start(startInfo);