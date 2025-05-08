import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SectraUrlLaunchSharedSecret {

    public static String Secure(String plainText, String base64EncryptionKey) {
        return SectraUrlLaunchSharedSecret.Secure(plainText, Base64.getDecoder().decode(base64EncryptionKey));
    }

    public static String Secure(String plainText, byte[] encryptionKey) {
        try {
            int nonceLength = 12;
            int keyLength = 32;
            String CipherKeyDomainIdentifier = "sectra/encryptedonetimesignature/cipherkey";
            String SignatureKeyDomainIdentifier = "sectra/encryptedonetimesignature/signaturekey";

            // Generate nonce
            byte[] nonce = new byte[nonceLength];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(nonce);

            byte[] cipherKey = deriveKey(encryptionKey, keyLength, CipherKeyDomainIdentifier, nonce);
            byte[] signatureKey = deriveKey(encryptionKey, keyLength, SignatureKeyDomainIdentifier, nonce);

            byte[] encryptedText = EncryptionUtils.encrypt(plainText.getBytes(StandardCharsets.UTF_8), cipherKey);
            byte[] signedText = SignatureUtils.sign(encryptedText, signatureKey);

            byte[] encryptedAndSignedText = new byte[nonce.length + signedText.length];
            System.arraycopy(nonce, 0, encryptedAndSignedText, 0, nonce.length);
            System.arraycopy(signedText, 0, encryptedAndSignedText, nonce.length, signedText.length);

            String base64Result = Base64.getEncoder().encodeToString(encryptedAndSignedText);

            // Concatenate "sharedSecretEncryptedUrlQuery=" to the encoded string
            return "sharedSecretEncryptedUrlQuery=" + URLEncoder.encode(base64Result, java.nio.charset.StandardCharsets.UTF_8.toString());

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] deriveKey(byte[] key, int keyByteSize, String signatureKeyDomainIdentifier, byte[] nonce) throws InvalidKeyException, NoSuchAlgorithmException {
        // Concatenate SignatureKeyDomainIdentifier and nonce
        byte[] domainIdentifierBytes = signatureKeyDomainIdentifier.getBytes(StandardCharsets.UTF_8);
        byte[] info = new byte[domainIdentifierBytes.length + nonce.length];
        System.arraycopy(domainIdentifierBytes, 0, info, 0, domainIdentifierBytes.length);
        System.arraycopy(nonce, 0, info, domainIdentifierBytes.length, nonce.length);

        // Derive the cipherKey using HKDF
        return Hkdf.derive(key, 32, info);
    }
}
