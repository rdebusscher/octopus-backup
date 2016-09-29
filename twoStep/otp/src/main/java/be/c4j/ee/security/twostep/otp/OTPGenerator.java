package be.c4j.ee.security.twostep.otp;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.twostep.otp.config.OTPConfig;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.xml.bind.DatatypeConverter;

/**
 *
 */
@ApplicationScoped
public class OTPGenerator {

    @Inject
    private OTPConfig config;

    @Inject
    private OTPProviderFactory providerFactory;

    private int length;

    @PostConstruct
    public void init() {
        length = config.getOTPLength();
    }

    public String generate(OTPUserData data) {
        OTPProvider otpProvider = providerFactory.retrieveOTPProvider(length);
        return otpProvider.generate(data);
    }

}
