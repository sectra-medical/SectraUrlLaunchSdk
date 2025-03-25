## About

Sectra.UrlLaunch.SharedSecret is used for encrypting URL-launch strings using a key. More documentation is available at [the GitHub repository](https://github.com/sectra-medical/SectraUrlLaunchSdk).

## How to use

```
// Query string is created dynamically
var queryString = "user_id=MyUserId&time=1742896526"

// Key must be 32 bytes and can be either a byte array or base 64 encoded.
var base64Key = "EpNnJ5vPSEL5vqSgG7Oe8fzgICZ3pzcqn1bEoHqzDA8=";

var encryptedQueryString = Sectra.UrlLaunch.SharedSecret.SectraSharedSecretEncryption.Secure(queryString, base64Key);
```

## Related Packages

* Sectra Url Access String: [Sectra.UrlLaunch.UrlAccessString](https://www.nuget.org/packages/Sectra.UrlLaunch.UrlAccessString/)
* Sectra UrlLaunch PKI: [Sectra.UrlLaunch.Pki](https://www.nuget.org/packages/Sectra.UrlLaunch.Pki/)

## Feedback

Sectra.UrlLaunch.SharedSecret is released as open source under the [MIT license](https://github.com/sectra-medical/SectraUrlLaunchSdk/blob/main/LICENSE). Bug reports and contributions are welcome at [the GitHub repository](https://github.com/sectra-medical/SectraUrlLaunchSdk).
