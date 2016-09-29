package be.c4j.ee.security.twostep.otp;

import java.util.Properties;

/**
 *
 */
public interface OTPProvider {

    String generate(OTPUserData data);

    void setProperties(int digits, Properties properties);

    boolean supportValidate();

    boolean valid(OTPUserData data, int window, String userOTP);
}
