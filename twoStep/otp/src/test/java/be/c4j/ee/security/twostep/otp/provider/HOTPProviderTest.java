package be.c4j.ee.security.twostep.otp.provider;

import be.c4j.ee.security.twostep.otp.OTPProvider;
import be.c4j.ee.security.twostep.otp.OTPUserData;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class HOTPProviderTest {

    private static final int OTP_LENGTH = 6;

    @Test
    public void generate() {
        byte[] key = new byte[16];

        SecureRandom random = new SecureRandom();
        random.nextBytes(key);

        HOTPProvider provider = new HOTPProvider();
        configure(provider);
        OTPUserData userData = getUserData(key, 0);
        String otp = provider.generate(userData);

        assertThat(otp).hasSize(OTP_LENGTH);
        Long.valueOf(otp);  // When this doesn't fail, we know it has only digits

        String otp2 = provider.generate(userData);  // userData.value is updated
        assertThat(otp).isNotEqualTo(otp2); // At least we know we are able to generate different values
    }

    private void configure(OTPProvider provider) {
        provider.setProperties(OTP_LENGTH, new Properties());
    }

    private OTPUserData getUserData(byte[] key, long base) {
        return new OTPUserData(key, 0);
    }

    @Test
    public void generate_repeatableType1() {
        byte[] key = new byte[16];

        SecureRandom random = new SecureRandom();
        random.nextBytes(key);

        HOTPProvider provider = new HOTPProvider();
        configure(provider);
        OTPUserData userData = getUserData(key, 0);
        String otp = provider.generate(userData);

        provider = new HOTPProvider();
        configure(provider);
        userData = getUserData(key, 0); // regenerate as userdata.value is updated.
        String otp2 = provider.generate(userData);

        assertThat(otp).isEqualTo(otp2); // Same key, so same
    }

    @Test
    public void generate_repeatableType2() {
        byte[] key = new byte[16];

        SecureRandom random = new SecureRandom();
        random.nextBytes(key);

        HOTPProvider provider = new HOTPProvider();
        configure(provider);
        OTPUserData userData = getUserData(key, 0);
        String otp = provider.generate(userData);

        random.nextBytes(key); // Other secret
        provider = new HOTPProvider();
        configure(provider);
        userData = getUserData(key, 0);
        String otp2 = provider.generate(userData);

        assertThat(otp).isNotEqualTo(otp2); // other key, so different
    }

}