/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.credentials.authentication.oauth2;

import be.c4j.ee.security.config.OctopusJSFConfig;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.enterprise.inject.Specializes;

/**
 *
 */
@Specializes
public class OAuth2Configuration extends OctopusJSFConfig {

    public static final String APPLICATION = "application";

    @Override
    public String getLoginPage() {
        return "DYNAMIC OAUTH2 BASED";
    }

    @ConfigEntry
    public String getClientId() {
        return ConfigResolver.getPropertyValue("OAuth2.clientId", "");
    }

    @ConfigEntry
    public String getClientSecret() {
        return ConfigResolver.getPropertyValue("OAuth2.clientSecret", "");
    }
}
