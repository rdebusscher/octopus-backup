package be.c4j.ee.security.twostep.otp;

/**
 * Not all data, if any data at all, is used by a certain OTPProvider
 */
public class OTPUserData {

    private byte[] key;
    private Long value;  // The counter for HOTP, the time slot for TOTP, ...

    public OTPUserData(byte[] key, Long value) {
        this.key = key;
        this.value = value;
    }

    public byte[] getKey() {
        return key;
    }

    public Long getValue() {
        return value;
    }

    public void setValue(long value) {
        this.value = value;
    }
}
