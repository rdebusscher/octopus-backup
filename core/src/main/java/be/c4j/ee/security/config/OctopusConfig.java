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
package be.c4j.ee.security.config;

import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.role.NamedRole;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import be.rubus.web.jerry.config.logging.ModuleConfig;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.apache.deltaspike.core.impl.config.PropertiesConfigSource;
import org.apache.deltaspike.core.spi.config.ConfigSource;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

@ApplicationScoped
public class OctopusConfig implements ModuleConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(OctopusConfig.class);
    private static final String OCTOPUS_CONFIG_PROPERTIES = "octopusConfig.properties";

    private Class<? extends Annotation> namedPermissionCheckClass;

    private Class<? extends NamedPermission> namedPermissionClass;

    private Class<? extends Annotation> namedRoleCheckClass;

    private Class<? extends NamedRole> namedRoleClass;

    protected OctopusConfig() {
    }

    @PostConstruct
    public void init() {

        // The properties read from a URL specified by -Doctopus.cfg
        OctopusConfigSource octopusConfigSource = new OctopusConfigSource();
        octopusConfigSource.loadProperties();
        List<ConfigSource> configSourcesToAdd = new ArrayList<ConfigSource>();
        configSourcesToAdd.add(octopusConfigSource);

        //The properties file octopusConfig.properties on the class path
        Properties configProperties = new Properties();
        try {
            InputStream resourceStream = OctopusConfig.class.getClassLoader()
                    .getResourceAsStream(OCTOPUS_CONFIG_PROPERTIES);
            if (resourceStream != null) {
                configProperties.load(resourceStream);


            } else {
                LOGGER.warn("File octopusConfig.properties not found.");
            }
        } catch (IOException e) {
            LOGGER.warn("Exception during reading of the octopusConfig.properties file");
        }

        configSourcesToAdd.add(new PropertiesConfigSource(configProperties) {

            @Override
            public int getOrdinal() {
                return 5;
            }

            @Override
            public String getConfigName() {
                return OCTOPUS_CONFIG_PROPERTIES;
            }
        });

        // Add the 2 additional sources. System properties are already supported by DeltaSpike
        ConfigResolver.addConfigSources(configSourcesToAdd);

    }

    @ConfigEntry
    public String getLocationSecuredURLProperties() {
        return ConfigResolver.getPropertyValue("securedURLs.file", "/WEB-INF/securedURLs.ini");
    }

    @ConfigEntry
    public String getNamedPermission() {
        return ConfigResolver.getPropertyValue("namedPermission.class", "");
    }

    @ConfigEntry
    public String getNamedPermissionCheck() {
        return ConfigResolver.getPropertyValue("namedPermissionCheck.class", "");
    }

    @ConfigEntry
    public String getNamedRole() {
        return ConfigResolver.getPropertyValue("namedRole.class", "");
    }

    @ConfigEntry
    public String getNamedRoleCheck() {
        return ConfigResolver.getPropertyValue("namedRoleCheck.class", "");
    }

    @ConfigEntry
    public String getAliasNameLoginbean() {
        return ConfigResolver.getPropertyValue("aliasNameLoginBean", "");
    }

    @ConfigEntry
    public String getLoginPage() {
        return ConfigResolver.getPropertyValue("loginPage", "/login.xhtml");
    }

    @ConfigEntry
    public String getLogoutPage() {
        return ConfigResolver.getPropertyValue("logoutPage", "/");
    }

    @ConfigEntry
    public String getUnauthorizedExceptionPage() {
        return ConfigResolver.getPropertyValue("unauthorizedExceptionPage", "/unauthorized.xhtml");
    }

    @ConfigEntry
    public String getHashAlgorithmName() {
        return ConfigResolver.getPropertyValue("hashAlgorithmName", "");
    }

    @ConfigEntry
    public String getSaltLength() {
        return ConfigResolver.getPropertyValue("saltLength", "0");
    }

    @ConfigEntry
    public String getPostIsAllowedSavedRequest() {
        return ConfigResolver.getPropertyValue("allowPostAsSavedRequest", "true");
    }

    @ConfigEntry
    public String getCacheManager() {
        return ConfigResolver.getPropertyValue("cacheManager.class", MemoryConstrainedCacheManager.class.getName());
    }

    @ConfigEntry
    public String getAdditionalShiroIniFileNames() {
        return ConfigResolver.getPropertyValue("additionalShiroIniFileNames", "classpath:shiro_extra.ini");
    }

    @ConfigEntry
    public String getIsGlobalAuditActive() {
        return ConfigResolver.getPropertyValue("globalAuditActive", "false");
    }

    public Class<? extends Annotation> getNamedPermissionCheckClass() {
        if (namedPermissionCheckClass == null && getNamedPermissionCheck().length() != 0) {

            try {
                namedPermissionCheckClass = (Class<? extends Annotation>) Class.forName(getNamedPermissionCheck());
            } catch (ClassNotFoundException e) {
                LOGGER.error("Class defined in configuration property namedPermissionCheck is not found", e);
            }
        }
        return namedPermissionCheckClass;
    }

    public Class<? extends NamedPermission> getNamedPermissionClass() {
        if (namedPermissionClass == null) {

            if (getNamedPermission().length() != 0) {
                try {
                    namedPermissionClass = (Class<? extends NamedPermission>) Class.forName(getNamedPermission());
                } catch (ClassNotFoundException e) {
                    LOGGER.error("Class defined in configuration property 'namedPermission' is not found", e);
                }
            }
        }
        return namedPermissionClass;
    }

    public Class<? extends Annotation> getNamedRoleCheckClass() {
        if (namedRoleCheckClass == null && getNamedRoleCheck().length() != 0) {

            try {
                namedRoleCheckClass = (Class<? extends Annotation>) Class.forName(getNamedRoleCheck());
            } catch (ClassNotFoundException e) {
                LOGGER.error("Class defined in configuration property namedPermissionCheck is not found", e);
            }
        }
        return namedRoleCheckClass;
    }

    public Class<? extends NamedRole> getNamedRoleClass() {
        if (namedRoleClass == null) {

            if (getNamedRole().length() != 0) {
                try {
                    namedRoleClass = (Class<? extends NamedRole>) Class.forName(getNamedRole());
                } catch (ClassNotFoundException e) {
                    LOGGER.error("Class defined in configuration property 'namedRole' is not found", e);
                }
            }
        }
        return namedRoleClass;
    }
}
