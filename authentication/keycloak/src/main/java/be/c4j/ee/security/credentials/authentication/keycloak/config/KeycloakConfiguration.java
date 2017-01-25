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

import be.c4j.ee.security.config.AbstractOctopusConfig;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import be.rubus.web.jerry.config.logging.ModuleConfig;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;

import javax.enterprise.context.ApplicationScoped;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

/**
 *
 */
@ApplicationScoped
public class KeycloakConfiguration extends AbstractOctopusConfig implements ModuleConfig {

    private static final Object LOCK = new Object();

    private KeycloakDeployment oidcDeployment;

    @ConfigEntry
    public String getLocationKeycloakFile() {
        String propertyValue = ConfigResolver.getPropertyValue("keycloak.file");
        if (propertyValue == null || propertyValue.trim().isEmpty()) {
            throw new OctopusConfigurationException("keycloak.file configuration property is required");
        }
        return propertyValue;
    }

    @ConfigEntry
    public String getScopes() {
        return ConfigResolver.getPropertyValue("keycloak.scopes", "");
    }

    @ConfigEntry
    public String getIdpHint() {
        return ConfigResolver.getPropertyValue("keycloak.idpHint", "");
    }

    @ConfigEntry
    public boolean getKeycloakSingleLogout() {
        String singleLogout = ConfigResolver.getPropertyValue("keycloak.single.logout", "true");
        return Boolean.valueOf(singleLogout);
    }

    public KeycloakDeployment getKeycloakDeployment() {

        if (oidcDeployment == null) {
            synchronized (LOCK) {
                if (oidcDeployment == null) {
                    createKeycloakDeployment();
                }
            }
        }
        return oidcDeployment;
    }

    private void createKeycloakDeployment() {
        InputStream is;
        File config = new File(getLocationKeycloakFile());
        if (config.exists() && config.canRead()) {
            try {
                is = new FileInputStream(config);
            } catch (FileNotFoundException e) {
                is = null;  // To be on the safe side.
            }
        } else {
            is = this.getClass().getClassLoader().getResourceAsStream(getLocationKeycloakFile());
        }

        if (is == null) {
            throw new OctopusConfigurationException("keycloak.file configuration value can't be interpreted as a valid file.");
        }

        oidcDeployment = KeycloakDeploymentBuilder.build(is);
    }

}
