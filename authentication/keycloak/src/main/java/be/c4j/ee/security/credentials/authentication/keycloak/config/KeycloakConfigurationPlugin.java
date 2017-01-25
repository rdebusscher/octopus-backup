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
package be.c4j.ee.security.credentials.authentication.keycloak.config;

import be.c4j.ee.security.config.ConfigurationPlugin;
import be.c4j.ee.security.config.PluginOrder;
import be.c4j.ee.security.credentials.authentication.keycloak.KeycloakUserFilter;
import be.c4j.ee.security.credentials.authentication.keycloak.filter.KeycloakAuthenticatingFilter;
import be.c4j.ee.security.credentials.authentication.keycloak.matcher.KeycloakCredentialsMatcher;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
@PluginOrder(85)
public class KeycloakConfigurationPlugin implements ConfigurationPlugin {

    @Override
    public void addConfiguration(Ini ini) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("user", KeycloakUserFilter.class.getName());

        mainSection.put("keycloak", KeycloakAuthenticatingFilter.class.getName());

        mainSection.put("keycloakMatcher", KeycloakCredentialsMatcher.class.getName());
        mainSection.put("credentialsMatcher.matcher", "$keycloakMatcher");

    }
}
