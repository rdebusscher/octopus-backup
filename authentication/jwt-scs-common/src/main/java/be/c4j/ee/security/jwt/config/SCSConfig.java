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
package be.c4j.ee.security.jwt.config;

import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.config.AbstractOctopusConfig;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.util.StringUtil;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import be.rubus.web.jerry.config.logging.ModuleConfig;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
@PublicAPI
public class SCSConfig extends AbstractOctopusConfig implements ModuleConfig {

    @Inject
    private StringUtil stringUtil;

    @Inject
    private JWTConfig jwtConfig;

    private JWTOperation jwtOperation;
    private JWEAlgorithm jweAlgorithm;
    private JWTSignature jwtSignature;

    @ConfigEntry
    public JWTOperation getJWTOperation() {
        if (jwtOperation == null) {
            defineParameterValues();
            checkParameterValues();
        }

        return jwtOperation;
    }

    private void checkParameterValues() {
        if (jweAlgorithm == JWEAlgorithm.AES && stringUtil.isEmpty(getAESTokenSecret())) {
            throw new OctopusConfigurationException("Parameter jwt.aes.secret is required when jwt.algorithms contains AES");
        }

        if (jweAlgorithm == JWEAlgorithm.EC && stringUtil.isEmpty(jwtConfig.getLocationJWKFile())) {
            throw new OctopusConfigurationException("Parameter jwk.file is required when jwt.algorithms contains EC");
        }

        if (jweAlgorithm == JWEAlgorithm.RSA && stringUtil.isEmpty(jwtConfig.getLocationJWKFile())) {
            throw new OctopusConfigurationException("Parameter jwk.file is required when jwt.algorithms contains RSA");
        }
    }

    private void defineParameterValues() {
        String value = ConfigResolver.getPropertyValue("jwt.algorithms", "");

        for (JWEAlgorithm algorithm : JWEAlgorithm.values()) {
            if (value.contains(algorithm.name())) {
                jweAlgorithm = algorithm;
            }
        }

        for (JWTSignature signature : JWTSignature.values()) {
            if (value.contains(signature.name())) {
                jwtSignature = signature;
            }
        }

        // TODO Is there any way we can verify if an invalid value is specified?

        if (jweAlgorithm != null) {
            jwtOperation = JWTOperation.JWE;
        } else {
            jwtOperation = JWTOperation.JWT;
        }
    }

    @ConfigEntry
    public JWTSignature getJwtSignature() {
        return jwtSignature;
    }

    @ConfigEntry(noLogging = true)
    public String getHMACTokenSecret() {
        String propertyValue = ConfigResolver.getPropertyValue("jwt.hmac.secret");
        if (stringUtil.isEmpty(propertyValue)) {
            throw new OctopusConfigurationException("Parameter jwt.hmac.secret is required");
            // It is required if we use the transfer of Octopus User in REST Call (
            // If we use the System option (SystemAccount version with process to Process communication) this is not needed
        }
        return propertyValue;
    }

    @ConfigEntry
    public JWEAlgorithm getJWEAlgorithm() {
        return jweAlgorithm;
    }

    @ConfigEntry(noLogging = true)
    public String getAESTokenSecret() {
        return ConfigResolver.getPropertyValue("jwt.aes.secret");
    }

    @ConfigEntry
    public String getServerName() {
        // Must be environment specific !!! (dev, test, ...) so that jwt tokens can't be used cross environment.
        // TODO Maybe a bit strange that we have the parameter named sso.xxx .
        // It is only required within the jwt part of Octopus SSO feature.
        return ConfigResolver.getPropertyValue("SSO.octopus.server.name", "octopus");
    }
}