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
 *
 */
package be.c4j.ee.security.twostep.otp.config;

import be.c4j.ee.security.config.AbstractOctopusConfig;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import be.rubus.web.jerry.config.logging.ModuleConfig;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class OTPConfig extends AbstractOctopusConfig implements ModuleConfig {

    @PostConstruct
    public void init() {
        defineConfigurationSources();
    }

    @ConfigEntry
    public String getOTPProvider() {
        return ConfigResolver.getPropertyValue("otp.provider", "DOTP");
    }

    @ConfigEntry
    public String getOTPConfigFile() {
        return ConfigResolver.getPropertyValue("otp.configFile", null);
    }

    @ConfigEntry
    public int getOTPLength() {
        int result;
        String value = ConfigResolver.getPropertyValue("otp.length", "6");
        try {
            result = Integer.valueOf(value);
        } catch (NumberFormatException e) {
            throw new OctopusConfigurationException("otp.length property must be numeric (Integer)");
        }
        return result;
    }
}
