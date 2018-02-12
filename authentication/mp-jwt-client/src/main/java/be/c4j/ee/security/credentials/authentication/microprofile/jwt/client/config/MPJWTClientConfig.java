/*
 * Copyright 2014-2018 Rudy De Busscher
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
package be.c4j.ee.security.credentials.authentication.microprofile.jwt.client.config;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.apache.shiro.util.StringUtils;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class MPJWTClientConfig {

    private static final String INVALID_VALUE_JWT_TOKEN_TIME_TO_LIVE = "Invalid value specified for parameter jwt.token.timeToLive, needs to be a positive integer value";

    @ConfigEntry
    public int getJWTTimeToLive() {
        String propertyValue = ConfigResolver.getPropertyValue("jwt.token.timeToLive", "2");
        Integer result;
        try {
            result = Integer.valueOf(propertyValue);
            if (result < 1) {
                throw new OctopusConfigurationException(INVALID_VALUE_JWT_TOKEN_TIME_TO_LIVE);
            }
        } catch (NumberFormatException e) {
            throw new OctopusConfigurationException(INVALID_VALUE_JWT_TOKEN_TIME_TO_LIVE);
        }
        return result;
    }

    @ConfigEntry
    public String getServerName() {
        String result = ConfigResolver.getPropertyValue("jwt.token.issuer");
        if (!StringUtils.hasText(result)) {
            throw new OctopusConfigurationException("Parameter 'jwt.token.issuer' is required when using MicroProfile JWT AUth module");
        }
        return result;
    }

}
