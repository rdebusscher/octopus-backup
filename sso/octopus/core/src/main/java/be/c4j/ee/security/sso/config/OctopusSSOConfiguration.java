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
package be.c4j.ee.security.sso.config;

import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.config.AbstractOctopusConfig;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.enterprise.context.ApplicationScoped;

/**
 * Only for the Server, but since OctopusSSOUserConverter is here in sso-core, we need to have another config.
 */

@ApplicationScoped
@PublicAPI
public class OctopusSSOConfiguration extends AbstractOctopusConfig {

    @ConfigEntry
    public String getKeysToFilter() {
        return ConfigResolver.getPropertyValue("SSO.user.info.filtered", "");
    }

}
