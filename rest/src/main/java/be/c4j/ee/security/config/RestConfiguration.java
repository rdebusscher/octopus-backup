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

import be.c4j.ee.security.shiro.NoRememberMeManager;
import be.c4j.ee.security.shiro.NoStorageEvaluator;
import be.c4j.ee.security.shiro.RestUserFilter;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
@PluginOrder(20)
public class RestConfiguration implements ConfigurationPlugin {
    @Override
    public void addConfiguration(Ini ini) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("userRest", RestUserFilter.class.getName());

        // Doesn't look in the cookies for the principal
        mainSection.put("noRemember", NoRememberMeManager.class.getName());
        mainSection.put("securityManager.rememberMeManager", "$noRemember");

        // Don't store principal into the session.
        mainSection.put("noStorageEvaluator", NoStorageEvaluator.class.getName());
        mainSection.put("securityManager.subjectDAO.sessionStorageEvaluator", "$noStorageEvaluator");
        // this isn't good enough since it uses the session if it is available.
        // mainSection.put("securityManager.subjectDAO.sessionStorageEvaluator.sessionStorageEnabled", "false");
        // Don't know what creates the session, it appears to be happening outside of Shiro.

    }
}
