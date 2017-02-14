/*
 * Copyright 2014-2017 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.sso.server.config;

import be.c4j.ee.security.config.AbstractOctopusConfig;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.enterprise.inject.Specializes;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 */
@Specializes
public class SSOServerConfiguration extends AbstractOctopusConfig {

    private final int cookieTimeToLive = 10;

    protected SSOServerConfiguration() {
    }

    @ConfigEntry
    public String getSSOCookieName() {
        return ConfigResolver.getPropertyValue("SSO.cookie.name", "OctopusSSOToken");
    }

    /**
     * Returns the value for the cookie in hours
     *
     * @return
     */
    @ConfigEntry
    public int getSSOCookieTimeToLive() {
        String timeToLive = ConfigResolver.getPropertyValue("SSO.cookie.timetolive", "10h");
        Pattern pattern = Pattern.compile("^(\\d+)([hdm])$");
        Matcher matcher = pattern.matcher(timeToLive);

        int result = 0;
        if (matcher.matches()) {

            if ("h".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.valueOf(matcher.group(1));
            }
            if ("d".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.valueOf(matcher.group(1)) * 24;
            }
            if ("m".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.valueOf(matcher.group(1)) * 24 * 30;
            }

            if (!(result > 0)) {
                LOGGER.warn("Invalid configuration value for SSO.cookie.timetolive = " + timeToLive + ". Using default of 10h");
                result = cookieTimeToLive;
            }

        } else {
            LOGGER.warn("Invalid configuration value for SSO.cookie.timetolive = " + timeToLive + ". Using default of 10h");
            result = cookieTimeToLive;
        }
        return result;
    }

    @ConfigEntry
    public String getSSOCookieSecure() {
        return ConfigResolver.getPropertyValue("SSO.cookie.secure", "true");
    }

}
