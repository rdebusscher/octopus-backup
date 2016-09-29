package be.c4j.ee.security.twostep.otp.provider;

import be.c4j.ee.security.twostep.otp.Base32;
import be.c4j.ee.security.twostep.otp.OTPProvider;
import be.c4j.ee.security.twostep.otp.OTPUserData;

import java.security.SecureRandom;
import java.util.Properties;

/**
 *
 */
public class SOTPProvider implements OTPProvider {

    private SecureRandom secureRandom = new SecureRandom();

    private int digits;

    @Override
    public String generate(OTPUserData data) {
        long byteLength = Math.round(digits * 5.0 / 8.0);
        byte[] buffer = new byte[(int) byteLength];
        secureRandom.nextBytes(buffer);

        return Base32.encode(buffer).substring(0, digits);
    }

    @Override
    public void setProperties(int digits, Properties properties) {

        this.digits = digits;
    }

    @Override
    public boolean supportValidate() {
        return false;
    }

    @Override
    public boolean valid(OTPUserData data, int window, String userOTP) {
        return false;
    }
}
