package be.c4j.ee.security.twostep.otp.provider;

import be.c4j.ee.security.twostep.otp.OTPProvider;
import be.c4j.ee.security.twostep.otp.OTPUserData;

import java.security.SecureRandom;
import java.util.Properties;

/**
 *
 */
public class DOTPProvider implements OTPProvider {

    private SecureRandom secureRandom = new SecureRandom();

    private int digits;

    @Override
    public String generate(OTPUserData data) {
        double max = Math.pow(10, digits);
        double min = Math.pow(10, digits - 1);
        int value = secureRandom.nextInt((int) (max - min)) + (int) min;
        return String.valueOf(value);
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
