## About

Sectra.UrlLaunch.UrlAccessString is used for generating plain text URL access strings. More documentation is available at [the GitHub repository](https://github.com/sectra-medical/SectraUrlLaunchSdk).

## How to use

```
// Create a plain text query string
var parameters = new Parameters {
    UserId = "MyUserName",
};
var plainTextQueryString = Sectra.UrlLaunch.UrlAccessString.QueryString.GetQueryStringWithCurrentTime(parameters);
```

## Related Packages

* Sectra UrlLaunch PKI: [Sectra.UrlLaunch.Pki](https://www.nuget.org/packages/Sectra.UrlLaunch.Pki/)
* Sectra UrlLaunch Shared Secret: [Sectra.UrlLaunch.SharedSecret](https://www.nuget.org/packages/Sectra.UrlLaunch.SharedSecret/)

## Feedback

Sectra.UrlLaunch.UrlAccessString is released as open source under the [MIT license](https://github.com/sectra-medical/SectraUrlLaunchSdk/blob/main/LICENSE). Bug reports and contributions are welcome at [the GitHub repository](https://github.com/sectra-medical/SectraUrlLaunchSdk).
