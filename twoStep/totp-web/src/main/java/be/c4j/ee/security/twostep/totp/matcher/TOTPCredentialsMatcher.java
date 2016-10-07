package be.c4j.ee.security.twostep.totp.matcher;

import be.c4j.ee.security.twostep.TwoStepCredentialsMatcher;
import be.c4j.ee.security.twostep.otp.OTPUserData;
import be.c4j.ee.security.twostep.totp.TOTPHandler;

/**
 *
 */
public class TOTPCredentialsMatcher implements TwoStepCredentialsMatcher {

    private TOTPHandler handler;
    private OTPUserData userData;

    public TOTPCredentialsMatcher(TOTPHandler handler, OTPUserData userData) {
        this.handler = handler;
        this.userData = userData;
    }

    @Override
    public boolean doTwoStepCredentialsMatch(Object twoStepCredentials) {
        return handler.validateTOTPValue(userData, (String) twoStepCredentials);
    }
}
