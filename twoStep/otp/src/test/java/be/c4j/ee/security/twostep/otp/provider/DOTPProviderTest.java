package be.c4j.ee.security.twostep.otp.provider;

import be.c4j.ee.security.twostep.otp.OTPProvider;
import org.junit.Test;

import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class DOTPProviderTest {

    private static final int OTP_LENGTH = 6;

    @Test
    public void generate() {
        DOTPProvider provider = new DOTPProvider();
        configure(provider);
        String value = provider.generate(null);
        assertThat(value).hasSize(OTP_LENGTH);
        Long.valueOf(value); // If no error, we know that we have only digits.
    }

    private void configure(OTPProvider provider) {
        provider.setProperties(OTP_LENGTH, new Properties());
    }

    @Test
    public void generate_noDoubles() {
        DOTPProvider provider = new DOTPProvider();
        configure(provider);
        String value1 = provider.generate(null);

        String value2 = provider.generate(null);
        assertThat(value1).isNotEqualTo(value2); // Will this is the first indication it doesn't generates doubles :)
    }



}