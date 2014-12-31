/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package be.c4j.ee.security.config;

import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.role.NamedRole;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import be.rubus.web.jerry.config.logging.ModuleConfig;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.util.Properties;

@ApplicationScoped
public class OctopusConfig implements ModuleConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(OctopusConfig.class);

    protected Properties configProperties;

    private Class<? extends Annotation> namedPermissionCheckClass;

    private Class<? extends NamedPermission> namedPermissionClass;

    private Class<? extends Annotation> namedRoleCheckClass;

    private Class<? extends NamedRole> namedRoleClass;

    protected OctopusConfig() {
    }

    @PostConstruct
    public void init() {
        configProperties = new Properties();
        try {
            InputStream resourceStream = OctopusConfig.class.getClassLoader()
                    .getResourceAsStream("octopusConfig.properties");
            if (resourceStream != null) {
                configProperties.load(resourceStream);
            } else {
                LOGGER.warn("File octopusConfig.properties not found.");
            }
        } catch (IOException e) {
            LOGGER.warn("Exception during reading of the octopusConfig.properties file");
        }

    }

    @ConfigEntry
    public String getLocationSecuredURLProperties() {
        return configProperties.getProperty("securedURLs.file", "/WEB-INF/securedURLs.ini");
    }

    @ConfigEntry
    public String getNamedPermission() {
        return configProperties.getProperty("namedPermission.class", "");
    }

    @ConfigEntry
    public String getNamedPermissionCheck() {
        return configProperties.getProperty("namedPermissionCheck.class", "");
    }

    @ConfigEntry
    public String getNamedRole() {
        return configProperties.getProperty("namedRole.class", "");
    }

    @ConfigEntry
    public String getNamedRoleCheck() {
        return configProperties.getProperty("namedRoleCheck.class", "");
    }

    @ConfigEntry
    public String getAliasNameLoginbean() {
        return configProperties.getProperty("aliasNameLoginBean", "");
    }

    @ConfigEntry
    public String getLoginPage() {
        return configProperties.getProperty("loginPage", "/login.xhtml");
    }

    @ConfigEntry
    public String getUnauthorizedExceptionPage() {
        return configProperties.getProperty("unauthorizedExceptionPage", "/unauthorized.xhtml");
    }

    @ConfigEntry
    public String getHashAlgorithmName() {
        return configProperties.getProperty("hashAlgorithmName", "");
    }

    @ConfigEntry
    public String getSaltLength() {
        return configProperties.getProperty("saltLength", "0");
    }

    @ConfigEntry
    public String getPostIsAllowedSavedRequest() {
        return configProperties.getProperty("allowPostAsSavedRequest", "true");
    }

    @ConfigEntry
    public String getCacheManager() {
        return configProperties.getProperty("cacheManager.class", MemoryConstrainedCacheManager.class.getName());
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
