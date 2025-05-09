/**
 * This program is used by the integration tests to run the encryption and decryption commands.
 * If you make changes here please run IntegrationTestRunner.sh.
 */

using System.Reflection;

if (args.Length != 3) {
    Console.WriteLine($"Usage: {Assembly.GetExecutingAssembly().GetName().Name} <command> <key> <data>");
    return 1;
}

var command = args[0];
var key = args[1];
var data = args[2];

if (command == "secure") {
    var encryptedData = Sectra.UrlLaunch.SharedSecret.SectraSharedSecretEncryption.Secure(data, key);
    Console.WriteLine(encryptedData);
} else if (command == "view") {
    var decryptedData = Sectra.UrlLaunch.SharedSecret.SectraSharedSecretEncryption.View(data, key);
    Console.WriteLine(decryptedData);
} else {
    Console.WriteLine($"Unknown command: {command}");
    return 1;
}
return 0;
