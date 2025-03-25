## About

Sectra.UrlLaunch.Pki is used for encrypting URL-launch strings using certificates. More documentation is available at [the GitHub repository](https://github.com/sectra-medical/SectraUrlLaunchSdk).

## How to use

```
// Query string is created dynamically
var queryString = "user_id=MyUserId&time=1742896526"

// Certificates are usually located in a certificate store
var integratingPartyCertData = System.IO.File.ReadAllBytes("integratingParty.pfx");
var integratingPartyCertificate = new X509Certificate2(integratingPartyCertData, "certificatePassword", X509KeyStorageFlags.PersistKeySet);
var sectraCertData = System.IO.File.ReadAllBytes("sectra.cer");
var sectraCertificate = new X509Certificate2(sectraCertData, "certificatePassword", X509KeyStorageFlags.PersistKeySet);

var encryptedQueryString = Sectra.UrlLaunch.Pki.SectraPkiEncryption.Secure(queryString, integratingPartyCertificate, sectraCertificate);
```

## Related Packages

* Sectra Url Access String: [Sectra.UrlLaunch.UrlAccessString](https://www.nuget.org/packages/Sectra.UrlLaunch.UrlAccessString/)
* Sectra UrlLaunch Shared Secret: [Sectra.UrlLaunch.SharedSecret](https://www.nuget.org/packages/Sectra.UrlLaunch.SharedSecret/)

## Feedback

Sectra.UrlLaunch.Pki is released as open source under the [MIT license](https://github.com/sectra-medical/SectraUrlLaunchSdk/blob/main/LICENSE). Bug reports and contributions are welcome at [the GitHub repository](https://github.com/sectra-medical/SectraUrlLaunchSdk).
