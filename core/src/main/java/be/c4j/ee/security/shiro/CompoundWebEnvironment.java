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
package be.c4j.ee.security.shiro;

import be.c4j.ee.security.config.ConfigurationPlugin;
import be.c4j.ee.security.config.ConfigurationPluginHelper;
import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.filter.GlobalFilterConfiguration;
import be.c4j.ee.security.hash.SimpleHashFactory;
import be.c4j.ee.security.log.InfoVersionLogging;
import be.c4j.ee.security.realm.OctopusRealmAuthenticator;
import be.c4j.ee.security.salt.HashEncoding;
import be.c4j.ee.security.salt.OctopusHashedCredentialsMatcher;
import be.c4j.ee.security.url.ProgrammaticURLProtectionProvider;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.config.IniFilterChainResolverFactory;
import org.apache.shiro.web.config.WebIniSecurityManagerFactory;
import org.apache.shiro.web.env.IniWebEnvironment;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static be.c4j.ee.security.OctopusConstants.DEFAULT_COOKIE_AGE_SECONDS;
import static be.c4j.ee.security.OctopusConstants.DEFAULT_COOKIE_NAME;

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
            // before the additional ones. So values in the shiro_extra.ini can override the defaults of Octopus
            configureRememberMe(ini);

            processAdditionalIniFiles(ini);

            ini.addSection(IniFilterChainResolverFactory.URLS); // Create the empty section

            Ini iniWithURLS = readURLPatterns();

            addManuallyConfiguredUrls(ini.getSection(IniFilterChainResolverFactory.URLS), iniWithURLS
                    .getSection(APP_URL));

            configureCache(ini);
            configureSessionStorageEvaluator(ini);

            addPluginConfiguration(ini);

            String hashAlgorithmName = config.getHashAlgorithmName();
            if (!hashAlgorithmName.isEmpty()) {
                checkHashAlgorithmName(hashAlgorithmName);
                addHashedCredentialsConfig(ini, hashAlgorithmName);
            }

            addAuthenticationListener(ini);
        } catch (ConfigurationException ex) {
            LOGGER.error("Exception during configuration of Apache Shiro", ex);
        }

        if (config.showDebugFor().contains(Debug.INI)) {
            logIniContents(ini);
        }

        InfoVersionLogging versionLogging = BeanProvider.getContextualReference(InfoVersionLogging.class);
        versionLogging.showVersionInfo();

        super.setIni(ini);
    }

    private void configureRememberMe(Ini ini) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("securityManager.rememberMeManager.cookie.name", config.getRememberMeCookieName());
        mainSection.put("securityManager.rememberMeManager.cookie.maxAge", String.valueOf(config.getRememberMeCookieAge()));

        if (StringUtils.hasText(config.getRememberMeCookieEncryptionKey())) {
            mainSection.put("securityManager.rememberMeManager.cipherKey", String.valueOf(config.getRememberMeCookieEncryptionKey()));
        }
    }

    private String checkHashAlgorithmName(String hashAlgorithmName) {
        SimpleHashFactory factory = SimpleHashFactory.getInstance();
        return factory.defineRealHashAlgorithmName(hashAlgorithmName);
    }

    private void logIniContents(Ini ini) {
        // TODO use Logger?
        System.out.println("Shiro INI contents");
        for (Map.Entry<String, Ini.Section> entry : ini.entrySet()) {
            System.out.println("Section : " + entry.getKey());
            for (Map.Entry<String, String> sectionEntry : entry.getValue().entrySet()) {
                System.out.println(sectionEntry.getKey() + " = " + sectionEntry.getValue());
            }
        }
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
                        Map<String, String> sectionValues = new TreeMap<String, String>();
                        for (Map.Entry<String, String> sectionValue : sectionEntry.getValue().entrySet()) {
                            if (shiroKeyAllowed(sectionValue.getKey())) {
                                sectionValues.put(sectionValue.getKey(), sectionValue.getValue());
                            }
                        }
                        section.putAll(sectionValues);
                    }
                }
            }
        }
    }

    /**
     * We need to make sure that some values in the shiro_extra.ini doesn't overwrite the config defined in OctopusConfig.properties
     *
     * @param key
     * @return
     */
    private boolean shiroKeyAllowed(String key) {

        if ("securityManager.rememberMeManager.cookie.name".equals(key)
                && !DEFAULT_COOKIE_NAME.equals(config.getRememberMeCookieName())) {
            return false;
        }

        if ("securityManager.rememberMeManager.cookie.maxAge".equals(key)
                && DEFAULT_COOKIE_AGE_SECONDS != config.getRememberMeCookieAge()) {
            return false;
        }

        if ("securityManager.rememberMeManager.cipherKey".equals(key)
                && StringUtils.hasText(config.getRememberMeCookieEncryptionKey())) {
            return false;
        }

        return true;
    }

    private void configureCache(Ini ini) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("cacheManager", config.getCacheManager());
        mainSection.put("appRealm.cacheManager", "$cacheManager");
        mainSection.put("securityManager.cacheManager", "$cacheManager");
    }

    private void configureSessionStorageEvaluator(Ini ini) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("octopusSessionStorageEvaluator", OctopusSessionStorageEvaluator.class.getName());
        mainSection.put("securityManager.subjectDAO.sessionStorageEvaluator", "$octopusSessionStorageEvaluator");
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

    private void orderURLProtectionProviders(List<ProgrammaticURLProtectionProvider> providers) {
        Collections.sort(providers, new URLProtectionProviderComparator());
    }

    private void addAuthenticationListener(Ini ini) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("OctopusAuthenticator", OctopusRealmAuthenticator.class.getName());
        mainSection.put("securityManager.authenticator", "$OctopusAuthenticator");
    }

    private void addHashedCredentialsConfig(Ini ini, String someHashAlgorithmName) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);

        mainSection.put("hashedMatcher", OctopusHashedCredentialsMatcher.class.getName());
        mainSection.put("hashedMatcher.hashAlgorithmName", someHashAlgorithmName);
        if (config.getHashEncoding() != HashEncoding.HEX) {
            mainSection.put("hashedMatcher.storedCredentialsHexEncoded", "false");
        }
        mainSection.put("hashedMatcher.hashIterations", String.valueOf(config.getHashIterations()));
        ConfigurationPluginHelper.addToList(ini, IniSecurityManagerFactory.MAIN_SECTION_NAME, "credentialsMatcher.matchers", "$hashedMatcher");
    }

    private Ini readURLPatterns() {
        Ini iniWithURLS = createIni(config.getLocationSecuredURLProperties(), false);

        //securedURLs.ini is optional since 0.9.7
        if (iniWithURLS == null) {
            iniWithURLS = new Ini();
        }

        if (iniWithURLS.getSectionProperty(APP_URL, "/**") != null) {
            LOGGER.warn("securedURLs.ini file contains /** definition and thus blocks programmatic URL definition (by system or developer)");
        }
        List<ProgrammaticURLProtectionProvider> urlProtectionProviders = BeanProvider.getContextualReferences(ProgrammaticURLProtectionProvider.class, true);

        orderURLProtectionProviders(urlProtectionProviders);

        for (ProgrammaticURLProtectionProvider urlProtectionProvider : urlProtectionProviders) {
            for (Map.Entry<String, String> entry : urlProtectionProvider.getURLEntriesToAdd().entrySet()) {

                iniWithURLS.setSectionProperty(APP_URL, entry.getKey(), entry.getValue());
            }
        }

        iniWithURLS.setSectionProperty(APP_URL, "/**", "anon");
        return iniWithURLS;
    }

    private void addManuallyConfiguredUrls(Ini.Section target, Ini.Section source) {
        Boolean globalAudit = Boolean.valueOf(config.getIsGlobalAuditActive());

        List<GlobalFilterConfiguration> globalFilterConfigurations = BeanProvider.getContextualReferences(GlobalFilterConfiguration.class, true);

        for (Map.Entry<String, String> entry : source.entrySet()) {
            String value = entry.getValue();

            String url = entry.getKey();
            if (!url.startsWith("/")) {
                url = '/' + url;
            }

            List<String> additionalFilters = new ArrayList<String>();

            if (globalAudit) {
                additionalFilters.add("audit");
            }

            for (GlobalFilterConfiguration globalFilterConfiguration : globalFilterConfigurations) {
                additionalFilters.addAll(globalFilterConfiguration.addFiltersTo(url));

            }

            if (!additionalFilters.isEmpty()) {
                StringBuilder filters = new StringBuilder();
                filters.append(value);
                for (String additionalFilter : additionalFilters) {
                    filters.append(", ").append(additionalFilter);
                }
                value = filters.toString();
            }

            target.put(url, value);
        }
    }

    @Override
    protected void configure() {
        // Copied From super class with : calling the  createOctopusSecurityManager() and createOctopusFilterChainResolver
        this.objects.clear();

        WebSecurityManager securityManager = createOctopusSecurityManager();
        setWebSecurityManager(securityManager);

        FilterChainResolver resolver = createOctopusFilterChainResolver();
        if (resolver != null) {
            setFilterChainResolver(resolver);
        }

    }

    private WebSecurityManager createOctopusSecurityManager() {
        // Based on super.createWebSecurityManager
        WebIniSecurityManagerFactory factory;
        Ini ini = getIni();
        if (CollectionUtils.isEmpty(ini)) {
            factory = new OctopusSecurityManagerFactory();
        } else {
            factory = new OctopusSecurityManagerFactory(ini);
        }

        WebSecurityManager wsm = (WebSecurityManager) factory.getInstance();

        //SHIRO-306 - get beans after they've been created (the call was before the factory.getInstance() call,
        //which always returned null.
        Map<String, ?> beans = factory.getBeans();
        if (!CollectionUtils.isEmpty(beans)) {
            this.objects.putAll(beans);
        }

        return wsm;

    }

    private FilterChainResolver createOctopusFilterChainResolver() {

        FilterChainResolver resolver = null;

        Ini ini = getIni();

        if (!CollectionUtils.isEmpty(ini)) {
            //only create a resolver if the 'filters' or 'urls' sections are defined:
            Ini.Section urls = ini.getSection(IniFilterChainResolverFactory.URLS);
            Ini.Section filters = ini.getSection(IniFilterChainResolverFactory.FILTERS);
            if (!CollectionUtils.isEmpty(urls) || !CollectionUtils.isEmpty(filters)) {
                //either the urls section or the filters section was defined.  Go ahead and create the resolver:
                IniFilterChainResolverFactory factory = new OctopusIniFilterChainResolverFactory(ini, this.objects);
                resolver = factory.getInstance();
            }
        }

        return resolver;
    }

}
