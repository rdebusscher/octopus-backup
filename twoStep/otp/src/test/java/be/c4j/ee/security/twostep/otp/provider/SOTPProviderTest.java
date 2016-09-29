package be.c4j.ee.security.twostep.otp.provider;

import be.c4j.ee.security.twostep.otp.OTPProvider;
import org.junit.Test;

import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class SOTPProviderTest {

    private static final int OTP_LENGTH = 6;

    @Test
    public void generate() {
        SOTPProvider provider = new SOTPProvider();
        configure(provider);
        String value = provider.generate(null);
        assertThat(value).hasSize(OTP_LENGTH);
        System.out.println(value);
    }

    private void configure(OTPProvider provider) {
        provider.setProperties(OTP_LENGTH, new Properties());
    }

    @Test
    public void generate_noDoubles() {
        SOTPProvider provider = new SOTPProvider();
        configure(provider);
        String value1 = provider.generate(null);
        String value2 = provider.generate(null);

        assertThat(value1).isNotEqualTo(value2);
    }

}