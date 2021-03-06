/*
 * Copyright 2014-2018 Rudy De Busscher (www.c4j.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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