import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;

class SignatureUtils {
    private static final int NonceByteCount = 32;
    private static final long TICKS_AT_EPOCH = 621355968000000000L;
    private static final long TICKS_PER_MILLISECOND = 10000;
    private static final long KIND_UTC = 0x4000000000000000L; // Bit for DateTimeKind.Utc

    public static byte[] sign(byte[] data, byte[] key) throws Exception {
        byte[] packed = pack(data);
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        hmac.init(keySpec);
        byte[] mac = hmac.doFinal(packed);

        byte[] signatureMessage = new byte[mac.length + packed.length];
        System.arraycopy(mac, 0, signatureMessage, 0, mac.length);
        System.arraycopy(packed, 0, signatureMessage, mac.length, packed.length);

        return signatureMessage;
    }

    private static byte[] pack(byte[] data) throws Exception {
        // Current UTC time
        Instant now = Instant.now();

        // Calculate the number of ticks since 1/1/0001 00:00:00.000
        long ticks = TICKS_AT_EPOCH + (now.toEpochMilli() * TICKS_PER_MILLISECOND);

        // Set the 62nd bit to 1 to indicate DateTimeKind.Utc
        ticks |= KIND_UTC;

        // Convert ticks to byte array for C# compatibility
        byte[] timestamp = ByteBuffer.allocate(Long.BYTES).order(ByteOrder.LITTLE_ENDIAN).putLong(ticks).array();

        byte[] nonce = new byte[NonceByteCount];
        new SecureRandom().nextBytes(nonce);

        byte[] packedData = new byte[timestamp.length + nonce.length + data.length];
        System.arraycopy(timestamp, 0, packedData, 0, timestamp.length);
        System.arraycopy(nonce, 0, packedData, timestamp.length, nonce.length);
        System.arraycopy(data, 0, packedData, timestamp.length + nonce.length, data.length);

        return packedData;
    }
}