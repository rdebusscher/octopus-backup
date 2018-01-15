package be.c4j.ee.security.config;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


public class CookieAgeConfigTest {

    private CookieAgeConfig cookieAgeConfig = new CookieAgeConfig();

    @Test
    public void getCookieAge_1()  {

        assertThat(cookieAgeConfig.getCookieAge("1h")).isEqualTo(3600);
    }

    @Test
    public void getCookieAge_2()  {

        assertThat(cookieAgeConfig.getCookieAge("3h")).isEqualTo(3600 * 3);
    }

    @Test
    public void getCookieAge_3()  {

        assertThat(cookieAgeConfig.getCookieAge("1d")).isEqualTo(3600 * 24);
    }

    @Test(expected = OctopusConfigurationException.class)
    public void getCookieAge_negative()  {

        cookieAgeConfig.getCookieAge("-1h");
    }

}