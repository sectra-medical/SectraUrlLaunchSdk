import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

class EncryptionUtils {
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final int TAG_LENGTH_BYTE = 16;
    private static final int TAG_LENGTH_BIT = TAG_LENGTH_BYTE * 8;
    private static final int NONCE_LENGTH_BYTE = 12;

    public static byte[] encrypt(byte[] plainText, byte[] key) throws Exception {
        byte[] nonce = new byte[NONCE_LENGTH_BYTE];
        secureRandom.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, nonce);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

        byte[] cipherText = cipher.doFinal(plainText);

        byte[] encryptedMessage = new byte[1 + nonce.length + cipherText.length];
        encryptedMessage[0] = 2; // Version "2" compatible with the Shared Secret algorithm in .net 6+

        // Copy nonce and ciphertext into the encryptedMessage
        System.arraycopy(nonce, 0, encryptedMessage, 1, nonce.length);

        // The Java AES implementation adds the TAG bytes at the end but the Shared Secret algorithm expects the TAG first
        System.arraycopy(cipherText, cipherText.length - TAG_LENGTH_BYTE, encryptedMessage, 1 + nonce.length, TAG_LENGTH_BYTE);
        System.arraycopy(cipherText, 0, encryptedMessage, 1 + nonce.length + TAG_LENGTH_BYTE, cipherText.length - TAG_LENGTH_BYTE);

        return encryptedMessage;
    }
}