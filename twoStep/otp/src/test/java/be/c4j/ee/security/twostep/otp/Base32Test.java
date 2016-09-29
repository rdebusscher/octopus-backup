package be.c4j.ee.security.twostep.otp;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class Base32Test {
    @Test
    public void encode()  {
        String encode = Base32.encode("test".getBytes());
        assertThat(encode).isEqualTo("ORSXG5A");
    }

    @Test
    public void decode() throws Base32.DecodingException {
        byte[] value = Base32.decode("ORSXG5A");
        assertThat("test").isEqualTo(new String(value));

    }

}