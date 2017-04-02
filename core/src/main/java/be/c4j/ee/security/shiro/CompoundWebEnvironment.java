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
package be.c4j.ee.security.shiro;

import be.c4j.ee.security.config.ConfigurationPlugin;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.filter.GlobalFilterConfiguration;
import be.c4j.ee.security.realm.OctopusRealmAuthenticator;
import be.c4j.ee.security.salt.HashEncoding;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.web.config.IniFilterChainResolverFactory;
import org.apache.shiro.web.env.IniWebEnvironment;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class CompoundWebEnvironment extends IniWebEnvironment {

    private static final String APP_URL = "";
    private static final Logger LOGGER = LoggerFactory.getLogger(CompoundWebEnvironment.class);

    private OctopusConfig config;

    @Override
    public void init() {
        // config used by setIni which is called by super.init().
        config = BeanProvider.getContextualReference(OctopusConfig.class);
        super.init();
    }

    @Override
    public void setIni(Ini ini) {

        try {
            processAdditionalIniFiles(ini);

            ini.addSection(IniFilterChainResolverFactory.URLS); // Create the empty section
            addURLsWithNamedPermission(ini);

            Ini iniWithURLS = readURLPatterns();

            addManuallyConfiguredUrls(ini.getSection(IniFilterChainResolverFactory.URLS), iniWithURLS
                    .getSection(APP_URL));

            configureCache(ini);
            configureSessionStorageEvaluator(ini);

            String hashAlgorithmName = config.getHashAlgorithmName();
            if (!hashAlgorithmName.isEmpty()) {
                try {
                    MessageDigest.getInstance(hashAlgorithmName);
                } catch (NoSuchAlgorithmException e) {
                    throw new IllegalArgumentException("Hash algorithm name unknown : " + hashAlgorithmName, e);
                }
                addHashedCredentialsConfig(ini, hashAlgorithmName);
            }

            addPluginConfiguration(ini);

            addAuthenticationListener(ini);
        } catch (ConfigurationException ex) {
            LOGGER.error("Exception during configuration of Apache Shiro", ex);
        }

        super.setIni(ini);
    }

    private void processAdditionalIniFiles(Ini ini) {
        String additionalShiroIniFileNames = config.getAdditionalShiroIniFileNames();
        if (additionalShiroIniFileNames != null && additionalShiroIniFileNames.trim().length() > 0) {
            String[] iniFileNames = additionalShiroIniFileNames.split(",");
            for (String iniFileName : iniFileNames) {

                Ini additionalIni = createIni(iniFileName, false);
                if (additionalIni != null) {
                    for (Map.Entry<String, Ini.Section> sectionEntry : additionalIni.entrySet()) {
                        Ini.Section section = ini.get(sectionEntry.getKey());
                        Map<String, String> sectionValues = new HashMap<String, String>();
                        for (Map.Entry<String, String> sectionValue : sectionEntry.getValue().entrySet()) {
                            sectionValues.put(sectionValue.getKey(), sectionValue.getValue());
                        }
                        section.putAll(sectionValues);
                    }
                }
            }
        }
    }

    private void configureCache(Ini ini) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("cacheManager", config.getCacheManager());
    }

    private void configureSessionStorageEvaluator(Ini ini) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("octopusSessionStorageEvaluator", OctopusSessionStorageEvaluator.class.getName());
    }

    private void addPluginConfiguration(Ini ini) {
        List<ConfigurationPlugin> plugins = BeanProvider.getContextualReferences(ConfigurationPlugin.class, true, false);
        orderPlugins(plugins);
        for (ConfigurationPlugin plugin : plugins) {
            plugin.addConfiguration(ini);
        }

    }

    private void orderPlugins(List<ConfigurationPlugin> plugins) {
        Collections.sort(plugins, new ConfigurationPluginComparator());
    }

    private void addAuthenticationListener(Ini ini) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("OctopusAuthenticator", OctopusRealmAuthenticator.class.getName());
        mainSection.put("securityManager.authenticator", "$OctopusAuthenticator");
    }

    private void addHashedCredentialsConfig(Ini ini, String someHashAlgorithmName) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("credentialsMatcher", HashedCredentialsMatcher.class.getName());
        mainSection.put("credentialsMatcher.hashAlgorithmName", someHashAlgorithmName);
        if (config.getHashEncoding() != HashEncoding.HEX) {
            mainSection.put("credentialsMatcher.storedCredentialsHexEncoded", "false");
        }
        mainSection.put("appRealm.credentialsMatcher", "$credentialsMatcher");
    }


    private Ini readURLPatterns() {
        Ini iniWithURLS = getSpecifiedIni(new String[]{config.getLocationSecuredURLProperties()});

        iniWithURLS.setSectionProperty(APP_URL, "/**", "anon");
        return iniWithURLS;
    }

    private void addManuallyConfiguredUrls(Ini.Section target, Ini.Section source) {
        Boolean globalAudit = Boolean.valueOf(config.getIsGlobalAuditActive());

        List<GlobalFilterConfiguration> globalFilterConfigurations = BeanProvider.getContextualReferences(GlobalFilterConfiguration.class, true);

        for (Map.Entry<String, String> entry : source.entrySet()) {
            String value = entry.getValue();

            List<String> additionalFilters = new ArrayList<String>();

            if (globalAudit) {
                additionalFilters.add("audit");
            }

            for (GlobalFilterConfiguration globalFilterConfiguration : globalFilterConfigurations) {
                additionalFilters.addAll(globalFilterConfiguration.addFiltersTo(entry.getKey()));

            }

            if (!additionalFilters.isEmpty()) {
                StringBuilder filters = new StringBuilder();
                filters.append(value);
                for (String additionalFilter : additionalFilters) {
                    filters.append(", ").append(additionalFilter);
                }
                value = filters.toString();
            }

            target.put(entry.getKey(), value);
        }
    }

    private void addURLsWithNamedPermission(Ini someIni) {
        URLPermissionProtector protector = BeanProvider.getContextualReference(URLPermissionProtector.class);
        protector.configurePermissions(someIni.getSection(IniFilterChainResolverFactory.URLS));
    }

    @Override
    protected WebSecurityManager createWebSecurityManager() {
        // TODO With 0.9.7 we can do this in the OctopusSecurityManagerFactory
        // So that SecurityManager is available with @StartupEvent
        WebSecurityManager securityManager = super.createWebSecurityManager();
        SecurityUtils.setSecurityManager(securityManager);
        return securityManager;
    }
}
