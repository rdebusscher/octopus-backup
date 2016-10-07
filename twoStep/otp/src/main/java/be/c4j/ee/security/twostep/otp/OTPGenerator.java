package be.c4j.ee.security.twostep.otp;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class OTPGenerator {

    @Inject
    private OTPProviderFactory providerFactory;

    public String generate(OTPUserData data) {
        OTPProvider otpProvider = providerFactory.retrieveOTPProvider();
        return otpProvider.generate(data);
    }

}
