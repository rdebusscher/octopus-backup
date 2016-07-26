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
package be.c4j.ee.security.config;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.role.NamedRole;
import be.c4j.ee.security.salt.HashEncoding;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import be.rubus.web.jerry.config.logging.ModuleConfig;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;

@ApplicationScoped
public class OctopusConfig extends AbstractOctopusConfig implements ModuleConfig {

    private Class<? extends Annotation> namedPermissionCheckClass;

    private Class<? extends NamedPermission> namedPermissionClass;

    private Class<? extends Annotation> namedRoleCheckClass;

    private Class<? extends NamedRole> namedRoleClass;

    private List<Debug> debugValues;

    protected OctopusConfig() {
    }

    @PostConstruct
    public void init() {
        defineConfigurationSources();
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
    public String getHashAlgorithmName() {
        return ConfigResolver.getPropertyValue("hashAlgorithmName", "");
    }

    @ConfigEntry
    public HashEncoding getHashEncoding() {
        HashEncoding result = HashEncoding.fromValue(ConfigResolver.getPropertyValue("hashEncoding", "HEX"));
        if (result == null) {
            throw new OctopusConfigurationException(
                    "The 'hashEncoding' parameter value " + ConfigResolver.getPropertyValue("hashEncoding", "HEX") + " isn't valid. Use 'HEX' or 'BASE64'.");
        }
        return result;
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

    @ConfigEntry
    public List<Debug> showDebugFor() {
        if (debugValues == null) {
            // TODO Do we need to make this thread-safe?
            List<Debug> result = new ArrayList<Debug>();
            String value = ConfigResolver.getPropertyValue("show.debug", "");
            String[] parts = value.split(",");
            for (String part : parts) {
                String code = part.trim();
                if (code.length() > 0) {
                    try {
                        Debug debug = Debug.valueOf(code);
                        result.add(debug);
                    } catch (IllegalArgumentException e) {
                        LOGGER.error("Value defined in the show.debug property unknown ", part);
                    }
                }
            }
            debugValues = result;
        }
        return debugValues;
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
