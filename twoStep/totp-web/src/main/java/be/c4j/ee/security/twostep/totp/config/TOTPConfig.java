/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.twostep.totp.config;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.twostep.otp.config.OTPConfig;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.enterprise.inject.Specializes;

/**
 *
 */
@Specializes
public class TOTPConfig extends OTPConfig {

    @Override
    public String getOTPProvider() {
        return "TOTP";
    }

    @ConfigEntry
    public int getSecretLength() {
        int result = 0;
        try {
            result = Integer.parseInt(ConfigResolver.getPropertyValue("totp.secret.length", "128"));
        } catch (NumberFormatException e) {
            throw new OctopusConfigurationException("totp.secret.length property must be numeric (Integer)");
        }
        return result;
    }

    @ConfigEntry
    public int getWindow() {
        int result = 0;
        try {
            result = Integer.parseInt(ConfigResolver.getPropertyValue("totp.window", "1"));
        } catch (NumberFormatException e) {
            throw new OctopusConfigurationException("totp.window property must be numeric (Integer)");
        }
        return result;
    }

}
