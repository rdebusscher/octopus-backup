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

import be.c4j.ee.security.jwt.config.JWTUserConfig;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class JWTClientConfig extends JWTUserConfig {

    @ConfigEntry
    public int getJWTTimeToLive() {
        String propertyValue = ConfigResolver.getPropertyValue("jwt.token.timeToLive", "2");
        // FIXME Cast NumberformatException
        return Integer.valueOf(propertyValue);
    }

}
