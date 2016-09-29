package be.c4j.ee.security.twostep.twilio.token;

import org.apache.shiro.authc.AuthenticationToken;

/**
 *
 */
public class OTPToken implements AuthenticationToken {

    private String otpValue;

    public OTPToken(String otpValue) {
        this.otpValue = otpValue;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return otpValue;
    }
}
