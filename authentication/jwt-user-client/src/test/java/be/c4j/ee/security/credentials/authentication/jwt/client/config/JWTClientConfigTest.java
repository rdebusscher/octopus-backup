package be.c4j.ee.security.credentials.authentication.jwt.client.config;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.test.TestConfigSource;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.junit.After;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class JWTClientConfigTest {

    private JWTClientConfig jwtClientConfig = new JWTClientConfig();

    @After
    public void teardown() {
        ConfigResolver.freeConfigSources();
    }

    @Test
    public void getJWTTimeToLive() {
        TestConfigSource.defineConfigValue("5");

        int timeToLive = jwtClientConfig.getJWTTimeToLive();
        assertThat(timeToLive).isEqualTo(5);
    }

    @Test
    public void getJWTTimeToLive_defaultValue() {

        int timeToLive = jwtClientConfig.getJWTTimeToLive();
        assertThat(timeToLive).isEqualTo(2);
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getJWTTimeToLive_invalidValue() {
        TestConfigSource.defineConfigValue("JUnit");

        jwtClientConfig.getJWTTimeToLive();
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getJWTTimeToLive_negativeValue() {
        TestConfigSource.defineConfigValue("-1");

        jwtClientConfig.getJWTTimeToLive();
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getJWTTimeToLive_zeroValue() {
        TestConfigSource.defineConfigValue("0");

        jwtClientConfig.getJWTTimeToLive();
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getJwtSignature() {
        // On the JWT User Client side, the JWT Signature is required!!

        jwtClientConfig.getJwtSignature();

    }


}