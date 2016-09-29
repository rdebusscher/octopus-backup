package be.c4j.ee.security.twostep.otp.persistence;

import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.twostep.otp.OTPUserData;

/**
 *
 */
public interface OTPUserDataPersistence {

    OTPUserData retrieveData(UserPrincipal userPrincipal);

    void storeData(UserPrincipal userPrincipal, OTPUserData otpUserData);
}
