package be.c4j.ee.security.sso.client.config;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.sso.SSOFlow;
import be.c4j.test.TestConfigSource;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.junit.After;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class OctopusSSOClientConfigurationTest {

    private OctopusSSOClientConfiguration configuration = new OctopusSSOClientConfiguration();

    @After
    public void teardown() {
        ConfigResolver.freeConfigSources();
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getSSOType_unknown() {
        TestConfigSource.defineConfigValue("token");
        configuration.getSSOType();
    }

    @Test
    public void getSSOType_singleApp() {
        TestConfigSource.defineConfigValue("id-token");
        assertThat(configuration.getSSOType()).isEqualTo(SSOFlow.IMPLICIT);
    }

    @Test
    public void getSSOType_multiApp() {
        Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("SSO.application", "app2");
        parameters.put("app1.SSO.flow", "id-token");
        parameters.put("app2.SSO.flow", "code");
        TestConfigSource.defineConfigValue(parameters);

        assertThat(configuration.getSSOType()).isEqualTo(SSOFlow.AUTHORIZATION_CODE);
    }

    @Test
    public void getSSOScopes() {
        assertThat(configuration.getSSOScopes()).isEqualTo("");
    }

}