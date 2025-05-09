import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

class Hkdf {

    public static byte[] derive(byte[] inputKey, int outputKeyByteLength, byte[] info) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] salt = new byte[32]; // RFC mandates zeroes if no salt is given.
        return derive(inputKey, salt, outputKeyByteLength, info);
    }

    public static byte[] derive(byte[] inputKey, byte[] salt, int outputKeyByteLength, byte[] info) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] prfKey = extract(salt, inputKey);
        return expand(prfKey, outputKeyByteLength, info);
    }

    private static byte[] extract(byte[] salt, byte[] inputKeyMaterial) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(salt, "HmacSHA256"));
        return hmac.doFinal(inputKeyMaterial);
    }

    private static byte[] expand(byte[] key, int outputKeyByteLength, byte[] info) throws NoSuchAlgorithmException, InvalidKeyException {
        final int hashByteLength = 32;
        int n = (int) Math.ceil((double) outputKeyByteLength / hashByteLength);
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(key, "HmacSHA256"));
        List<byte[]> t = new ArrayList<>();

        byte[] previousT = new byte[0];

        for (int i = 1; i <= n; i++) {
            hmac.update(previousT);
            if (info != null) {
                hmac.update(info);
            }
            hmac.update((byte) i);
            byte[] currentT = hmac.doFinal();
            t.add(currentT);
            previousT = currentT;
        }

        byte[] outputKey = new byte[outputKeyByteLength];
        List<Byte> tBytes = new ArrayList<>();
        for (byte[] array : t) {
            for (byte b : array) {
                tBytes.add(b);
            }
        }

        for (int i = 0; i < outputKeyByteLength; i++) {
            outputKey[i] = tBytes.get(i);
        }

        return outputKey;
    }
}