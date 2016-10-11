package be.c4j.ee.security.twostep.otp.persistence;

import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.twostep.otp.OTPUserData;
import org.slf4j.Logger;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.Serializable;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class DefaultOTPUserDataPersistence implements OTPUserDataPersistence {

    @Inject
    private Logger logger;

    private Map<Serializable, OTPUserData> storage;

    private SecureRandom secureRandom;

    @PostConstruct
    public void init() {
        if (this.getClass().equals(DefaultOTPUserDataPersistence.class)) {
            // Only executed when no @Specialized bean in defined.
            logger.warn("Please provide your own CDI @Specialized bean of DefaultOTPUserDataPersistence for production purposes.");
            logger.warn("The DefaultOTPUserDataPersistence should not be used in production as it doesn't keep OTP secrets between restarts");
            storage = new HashMap<Serializable, OTPUserData>();
        }
        secureRandom = new SecureRandom();

    }

    @Override
    public OTPUserData retrieveData(UserPrincipal userPrincipal) {
        OTPUserData result = storage.get(userPrincipal.getId());
        if (result == null) {
            byte[] secret = defineSecretFor(userPrincipal);
            result = new OTPUserData(secret, 0L);
            // The 2 parameter is only used for HOTP and there it has the default value of 0.

        }
        return result;
    }

    private byte[] defineSecretFor(UserPrincipal userPrincipal) {
        byte[] result = new byte[8];  // FIXME
        secureRandom.nextBytes(result);
        return result;
    }

    @Override
    public void storeData(UserPrincipal userPrincipal, OTPUserData otpUserData) {

    }
}