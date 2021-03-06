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
public class JWTConfig extends AbstractOctopusConfig implements ModuleConfig {

    @Inject
    private StringUtil stringUtil;

    @ConfigEntry
    public String getLocationJWKFile() {
        return ConfigResolver.getPropertyValue("jwk.file");
    }

    @ConfigEntry
    public boolean isSystemAccountsOnly() {
        String propertyValue = ConfigResolver.getPropertyValue("jwt.systemaccounts.only", "True");
        return Boolean.valueOf(propertyValue);
    }

    @ConfigEntry
    public String getSystemAccountsMapFile() {
        String propertyValue = ConfigResolver.getPropertyValue("jwt.systemaccounts.map");
        if (isSystemAccountsOnly() && stringUtil.isEmpty(propertyValue)) {
            throw new OctopusConfigurationException("jwt.systemaccounts.map configuration property is required when jwt.systemaccounts.only is set");
        }
        return propertyValue;
    }

}
