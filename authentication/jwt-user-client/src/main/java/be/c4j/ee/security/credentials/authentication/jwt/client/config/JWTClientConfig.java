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
package be.c4j.ee.security.credentials.authentication.jwt.client.config;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.jwt.config.JWEAlgorithm;
import be.c4j.ee.security.jwt.config.JWTOperation;
import be.c4j.ee.security.jwt.config.JWTSignature;
import be.c4j.ee.security.jwt.config.JWTUserConfig;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class JWTClientConfig {

    private static final String INVALID_VALUE_JWT_TOKEN_TIME_TO_LIVE = "Invalid value specified for parameter jwt.token.timeToLive, needs to be a positive integer value";

    @Inject
    private JWTUserConfig jwtUserConfig;

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

    // methods delegating to JWTUserConfig
    @ConfigEntry(noLogging = true)
    public String getHMACTokenSecret() {
        return jwtUserConfig.getHMACTokenSecret();
    }

    @ConfigEntry
    public JWTOperation getJWTOperation() {
        return jwtUserConfig.getJWTOperation();
    }

    @ConfigEntry
    public JWEAlgorithm getJWEAlgorithm() {
        return jwtUserConfig.getJWEAlgorithm();
    }

    @ConfigEntry
    public JWTSignature getJwtSignature() {
        JWTSignature signature = jwtUserConfig.getJwtSignature();
        if (signature == null) {
            throw new OctopusConfigurationException("No Algorithm specified for the JWT signature; parameter jwt.algorithm incorrect");
        }

        return signature;
    }

    @ConfigEntry
    public String getServerName() {
        return jwtUserConfig.getServerName();
    }

}
