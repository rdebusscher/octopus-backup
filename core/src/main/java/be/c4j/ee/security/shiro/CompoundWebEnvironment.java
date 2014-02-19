/*
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * /
 */
package be.c4j.ee.security.shiro;

import be.c4j.ee.security.config.SecurityModuleConfig;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.web.config.IniFilterChainResolverFactory;
import org.apache.shiro.web.env.IniWebEnvironment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class CompoundWebEnvironment extends IniWebEnvironment {

    private static final String APP_URL = "";
    private static final Logger LOGGER = LoggerFactory.getLogger(CompoundWebEnvironment.class);

    private SecurityModuleConfig config;

    @Override
    public void init() {
        // config used by setIni which is called by super.init().
        config = CodiUtils.getContextualReferenceByClass(SecurityModuleConfig.class);
        super.init();
    }

    @Override
    public void setIni(Ini ini) {

        try {
            ini.addSection(IniFilterChainResolverFactory.URLS); // Create the empty section
            addURLsWithNamedPermission(ini);

            Ini iniWithURLS = readURLPatterns();

            addManuallyConfiguredUrls(ini.getSection(IniFilterChainResolverFactory.URLS), iniWithURLS
                    .getSection(APP_URL));

            ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME).put("user.loginUrl", config.getLoginPage());

            String hashAlgorithmName = config.getHashAlgorithmName();
            if (hashAlgorithmName != null) {
                try {
                    MessageDigest.getInstance(hashAlgorithmName);
                } catch (NoSuchAlgorithmException e) {
                    throw new IllegalArgumentException("Hash algorithm name unknown : " + hashAlgorithmName, e);
                }
                addHashedCredentialsConfig(ini, hashAlgorithmName);
            }
        } catch (ConfigurationException ex) {
            LOGGER.error("Exception during configuration of Apache Shiro", ex);
        }

        super.setIni(ini);
    }

    private void addHashedCredentialsConfig(Ini ini, String someHashAlgorithmName) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("credentialsMatcher", HashedCredentialsMatcher.class.getName());
        mainSection.put("credentialsMatcher.hashAlgorithmName",someHashAlgorithmName);
        mainSection.put("appRealm.credentialsMatcher", "$credentialsMatcher");
    }

    private Ini readURLPatterns() {
        Ini iniWithURLS = getSpecifiedIni(new String[]{config.getLocationSecuredURLProperties()});

        iniWithURLS.setSectionProperty(APP_URL, "/**", "anon");
        return iniWithURLS;
    }

    private void addManuallyConfiguredUrls(Ini.Section target, Ini.Section source) {
        for (Map.Entry<String, String> entry: source.entrySet()) {
            target.put(entry.getKey(), entry.getValue());
        }
    }

    private void addURLsWithNamedPermission(Ini someIni) {
        URLPermissionProtector protector = CodiUtils.getContextualReferenceByClass(URLPermissionProtector.class);
        protector.configurePermissions(someIni.getSection(IniFilterChainResolverFactory.URLS));
    }
}
