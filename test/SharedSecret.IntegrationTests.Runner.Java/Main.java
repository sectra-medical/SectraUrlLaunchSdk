/**
 * This program is used by the integration tests to run the encryption and decryption commands.
 * If you make changes here please run IntegrationTestRunner.sh.
 */
import java.awt.Desktop;
import java.net.URI;

public class Main {
    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage arguments: Main.java <command> <key> <data>");
            return;
        }
        String command = args[0];
        String key = args[1];
        String data = args[2];

        if (command.equalsIgnoreCase("secure")) {
            String encryptedData = SectraUrlLaunchSharedSecret.Secure(data, key);
            System.out.println(encryptedData);
        } else {
            System.out.println("Unknown command: " + command);
        }
    }
}
