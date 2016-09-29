package be.c4j.ee.security.twostep.otp.provider;

import be.c4j.ee.security.twostep.otp.OTPUserData;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class TOTPProviderTest {

    private static final int OTP_LENGTH = 6;

    @Test
    public void generateTOTP() throws Exception {

        byte[] key = createSecret();

        TOTPProvider provider = new TOTPProvider();
        settingProperties(provider);

        String value = provider.generate(getUserData(key));
        assertThat(value).hasSize(OTP_LENGTH);

        Long.valueOf(value); // When no exception, we know it only contains digits
    }

    private void settingProperties(TOTPProvider provider) {
        Properties properties = new Properties();
        properties.setProperty("algorithm", "HmacSHA1");
        provider.setProperties(OTP_LENGTH, properties);
    }

    @Test
    public void generateTOTP_repeatable() throws Exception {

        byte[] key = createSecret();

        TOTPProvider provider = new TOTPProvider();
        settingProperties(provider);

        String value1 = provider.generate(getUserData(key));

        provider = new TOTPProvider();
        settingProperties(provider);

        String value2 = provider.generate(getUserData(key));

        assertThat(value1).isEqualTo(value2);
        // Well, the above will fail now and then because we can just be over one time slot to another.

    }

    private OTPUserData getUserData(byte[] key) {
        return new OTPUserData(key, 0);
    }

    private byte[] createSecret() {
        byte[] key = new byte[16];

        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        return key;
    }
    // TODO We need a mechanism to switch the times.
    // So that we can test the moving parts.

    @Test
    public void valid() {
        byte[] key = createSecret();

        TOTPProvider provider = new TOTPProvider();
        settingProperties(provider);

        String code = provider.generate(getUserData(key));

        provider = new TOTPProvider();
        settingProperties(provider);

        // Window = 1 ; Only valid values from previous window is allowed since this test method doesn't wait more then 30 sec.
        boolean valid = provider.valid(getUserData(key), 1, code);
        assertThat(valid).isTrue();
    }
}