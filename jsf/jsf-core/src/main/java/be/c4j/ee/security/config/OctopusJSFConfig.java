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

import be.rubus.web.jerry.config.logging.ConfigEntry;
import be.rubus.web.jerry.config.logging.ModuleConfig;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class OctopusJSFConfig extends AbstractOctopusConfig implements ModuleConfig {

    private SessionHijackingLevel sessionHijackingLevel;

    protected OctopusJSFConfig() {
    }

    @PostConstruct
    public void init() {
        defineConfigurationSources();
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
    public String getPostIsAllowedSavedRequest() {
        return ConfigResolver.getPropertyValue("allowPostAsSavedRequest", "true");
    }

    @ConfigEntry
    public SessionHijackingLevel getSessionHijackingLevel() {
        if (sessionHijackingLevel == null) {
            String value = ConfigResolver.getPropertyValue("session.hijacking.level", "ON");

            sessionHijackingLevel = SessionHijackingLevel.valueOf(value);
        }
        return sessionHijackingLevel;
    }

    @ConfigEntry
    public boolean getSingleSession() {

        String value = ConfigResolver.getPropertyValue("session.single", "true");
        return Boolean.valueOf(value);

    }

    @ConfigEntry
    public String getExcludePrimeFacesMobile() {
        return ConfigResolver.getPropertyValue("primefaces.mobile.exclusion", "false");
    }


}
