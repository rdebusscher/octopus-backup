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
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.enterprise.context.ApplicationScoped;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 */
@ApplicationScoped
public class SSOServerConfiguration extends AbstractOctopusConfig {

    private static final int COOKIE_TIME_TO_LIVE = 10;
    private static final int ACCESS_TOKEN_TIME_TO_LIVE = 3600;

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
                result = COOKIE_TIME_TO_LIVE;
            }

        } else {
            LOGGER.warn("Invalid configuration value for SSO.cookie.timetolive = " + timeToLive + ". Using default of 10h");
            result = COOKIE_TIME_TO_LIVE;
        }
        return result;
    }

    @ConfigEntry
    public String getSSOCookieSecure() {
        return ConfigResolver.getPropertyValue("SSO.cookie.secure", "true");
    }

    @ConfigEntry
    public int getOIDCTokenLength() {
        String propertyValue = ConfigResolver.getPropertyValue("SSO.token.length", "32");
        int result;
        try {
            result = Integer.valueOf(propertyValue);
        } catch (NumberFormatException e) {
            throw new OctopusConfigurationException("Configuration parameter value 'SSO.token.length' must be numeric and larger then 31");
        }

        if (result < 32) {
            throw new OctopusConfigurationException("Configuration parameter value 'SSO.token.length' must be numeric and larger then 31");
        }
        return result;
    }

    /**
     * Returns the value for the access token time to live in seconds
     *
     * @return
     */
    @ConfigEntry
    public int getSSOAccessTokenTimeToLive() {
        String timeToLive = ConfigResolver.getPropertyValue("SSO.access.token.timetolive", "1h");
        Pattern pattern = Pattern.compile("^(\\d+)([hms])$");
        Matcher matcher = pattern.matcher(timeToLive);

        int result = 0;
        if (matcher.matches()) {

            if ("h".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.valueOf(matcher.group(1)) * 60 * 60;
            }
            if ("m".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.valueOf(matcher.group(1)) * 60;
            }
            if ("s".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.valueOf(matcher.group(1));
            }

            if (!(result > 0)) {
                LOGGER.warn("Invalid configuration value for SSO.access.token.timetolive = " + timeToLive + ". Using default of 1h");
                result = ACCESS_TOKEN_TIME_TO_LIVE;
            }

        } else {
            LOGGER.warn("Invalid configuration value for SSO.access.token.timetolive = " + timeToLive + ". Using default of 10h");
            result = ACCESS_TOKEN_TIME_TO_LIVE;
        }
        return result;
    }

}
