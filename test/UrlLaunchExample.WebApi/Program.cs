using Sectra.UrlLaunch.SharedSecret;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var sharedSecretBase64KeyAppSettingsKey = "SharedSecretBase64Key";
var sharedSecretBase64Key = builder.Configuration[sharedSecretBase64KeyAppSettingsKey];

app.MapGet("/UrlLaunchExampleApi", (HttpContext context) => {
    var queryString = context.Request.QueryString.Value?.Split('?')[1] ?? string.Empty;
    var result = string.Empty;
    if (SectraSharedSecretEncryption.IsSharedSecretEncryption(queryString)) {
        if (string.IsNullOrEmpty(sharedSecretBase64Key)) {
            return Results.Problem($"appsettings.json key '{sharedSecretBase64KeyAppSettingsKey}' must contain a value");
        }
        try {
            queryString = SectraSharedSecretEncryption.View(queryString, sharedSecretBase64Key);
        }
        catch (Exception e) {
            // Do not expose exceptions to clients in production
            return Results.Problem(title: "Exception when decrypting", detail: e.Message);
        }
        result = $"Decrypted query: '{queryString}'";
    } else {
        // Nothing to decrypt
        result = $"Plain text query: '{queryString}'";
    }

    return Results.Ok(result);
});

app.Run();
