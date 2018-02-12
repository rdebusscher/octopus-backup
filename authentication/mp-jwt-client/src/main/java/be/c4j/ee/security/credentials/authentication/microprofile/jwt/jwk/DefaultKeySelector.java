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
package be.c4j.ee.security.credentials.authentication.microprofile.jwt.jwk;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.jwt.JWKManager;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.inject.Typed;

/**
 *
 */
@Typed
public class DefaultKeySelector implements KeySelector {

    private final Logger logger = LoggerFactory.getLogger(DefaultKeySelector.class);

    private JWKManager jwkManager;

    public DefaultKeySelector() {
        // We can't make this bean a CDI bean, the idea is that the Developer can define a CDI bean (based on KeySelector) and that that one should be choosen.
        // If we make this bean also CDI enabled, we have 2 beans implementing the same interface and an AmbiguousResolutionException
        jwkManager = BeanProvider.getContextualReference(JWKManager.class);
    }

    @Override
    public RSAKey selectSecretKey(String keyId, String url) {
        JWK result = null;
        if (StringUtils.hasText(keyId)) {
            if (jwkManager.existsApiKey(keyId)) {
                result = jwkManager.getJWKForApiKey(keyId);
            } else {
                if (jwkManager.hasSingleKey()) {
                    result = jwkManager.getSingleKey();
                    logger.warn(String.format("No key with kid '%s' found within the jwk.file but taken the single key", keyId));
                }
            }
        } else {
            if (jwkManager.hasSingleKey()) {
                result = jwkManager.getSingleKey();
            }
        }
        if (result == null) {
            return null;
        }
        if (!(result instanceof RSAKey)) {
            throw new OctopusConfigurationException("JWK for signing MP JWT Auth token must be of type RSA.");
        }
        return (RSAKey) result;
    }
}
