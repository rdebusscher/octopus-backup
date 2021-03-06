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
package be.c4j.ee.security.config;

import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.hash.SimpleHashFactory;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.role.NamedRole;
import be.c4j.ee.security.salt.HashEncoding;
import be.c4j.ee.security.util.StringUtil;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import be.rubus.web.jerry.config.logging.ModuleConfig;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.util.StringUtils;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;

import static be.c4j.ee.security.OctopusConstants.DEFAULT_COOKIE_AGE;
import static be.c4j.ee.security.OctopusConstants.DEFAULT_COOKIE_NAME;

@ApplicationScoped
@PublicAPI
public class OctopusConfig extends AbstractOctopusConfig implements ModuleConfig {

    private Class<? extends Annotation> namedPermissionCheckClass;

    private Class<? extends NamedPermission> namedPermissionClass;

    private Class<? extends Annotation> namedRoleCheckClass;

    private Class<? extends NamedRole> namedRoleClass;

    private Class<? extends Annotation> customCheckClass;

    private List<Debug> debugValues;

    private CookieAgeConfig cookieAgeConfig;

    @Inject
    private StringUtil stringUtil;

    protected OctopusConfig() {
        cookieAgeConfig = new CookieAgeConfig();
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
    public String getCustomCheck() {
        return ConfigResolver.getPropertyValue("customCheck.class", "");
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
    public Integer getHashIterations() {
        Integer result = null;
        String hashAlgorithmName = getHashAlgorithmName();
        if (!stringUtil.isEmpty(hashAlgorithmName)) {

            int defaultValue = SimpleHashFactory.getInstance().getDefaultHashIterations(hashAlgorithmName);
            String value = ConfigResolver.getPropertyValue("hashIterations", String.valueOf(defaultValue));

            try {
                result = Integer.parseInt(value);
            } catch (NumberFormatException e) {
                throw new OctopusConfigurationException(String.format("Parameter hashIterations must a a positive integer value : %s", e.getLocalizedMessage()));
            }
        }
        return result;
    }

    // TODO used on the OctopusUserFilter from the core, but basically only for JSF. So we should move OctopususerFilter to JSF Core?
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
    public boolean getIsSessionInvalidatedAtLogin() {
        return Boolean.valueOf(ConfigResolver.getPropertyValue("session.invalidate.login", "true"));
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

    @ConfigEntry
    public String getPermissionVoterSuffix() {
        return ConfigResolver.getPropertyValue("voter.suffix.permission", "PermissionVoter");
    }

    @ConfigEntry
    public String getRoleVoterSuffix() {
        return ConfigResolver.getPropertyValue("voter.suffix.role", "RoleVoter");
    }

    @ConfigEntry
    public String getCustomCheckSuffix() {
        return ConfigResolver.getPropertyValue("voter.suffix.check", "AccessDecisionVoter");
    }

    // TODO Remember-me is something specific for JSF but deeply integrated within core.
    // In a future version we need to pull it out of the core and make it JSF stuff only
    @ConfigEntry
    public String getRememberMeCookieName() {
        String propertyValue = ConfigResolver.getPropertyValue("rememberme.cookie.name", DEFAULT_COOKIE_NAME);
        if (!StringUtils.hasText(propertyValue)) {
            propertyValue = DEFAULT_COOKIE_NAME;
        }
        return propertyValue;
    }

    @ConfigEntry
    public int getRememberMeCookieAge() {
        String propertyValue = ConfigResolver.getPropertyValue("rememberme.cookie.maxage", DEFAULT_COOKIE_AGE);
        if (StringUtils.hasText(propertyValue)) {
            propertyValue = DEFAULT_COOKIE_AGE;
        }
        return cookieAgeConfig.getCookieAge(propertyValue);
    }


    @ConfigEntry
    public String getRememberMeCookieEncryptionKey() {
        String propertyValue = ConfigResolver.getPropertyValue("rememberme.cookie.cipherKey");
        if (StringUtils.hasText(propertyValue) && !Base64.isBase64(propertyValue.getBytes())) {
            throw new OctopusConfigurationException("Parameter 'rememberme.cookie.cipherKey' can only contain BASE64 characters.");
        }
        return propertyValue;
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

    public Class<? extends Annotation> getCustomCheckClass() {
        if (customCheckClass == null && getCustomCheck().length() != 0) {

            try {
                customCheckClass = (Class<? extends Annotation>) Class.forName(getCustomCheck());
            } catch (ClassNotFoundException e) {
                LOGGER.error("Class defined in configuration property customCheck is not found", e);
            }
        }
        return customCheckClass;
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
