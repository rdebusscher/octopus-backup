/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.c4j.ee.security.credentials.authentication.mp.config;

import be.c4j.ee.security.config.AbstractOctopusConfig;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import be.rubus.web.jerry.config.logging.ModuleConfig;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class MPConfiguration extends AbstractOctopusConfig implements ModuleConfig {

    @ConfigEntry
    public String getIssuer() {
        return ConfigResolver.getPropertyValue("mp.iss");
    }

    @ConfigEntry
    public String getAudience() {
        return ConfigResolver.getPropertyValue("mp.aud");
    }

}
