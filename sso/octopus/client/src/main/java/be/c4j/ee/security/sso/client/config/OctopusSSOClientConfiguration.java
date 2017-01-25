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
package be.c4j.ee.security.sso.client.config;

import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.annotation.PostConstruct;
import javax.enterprise.inject.Specializes;

/**
 *
 */
@Specializes
public class OctopusSSOClientConfiguration extends OctopusJSFConfig {

    private SSODataEncryptionHandler encryptionHandler;

    @PostConstruct
    public void init() {
        // Optional
        encryptionHandler = BeanProvider.getContextualReference(SSODataEncryptionHandler.class, true);
    }

    @Override
    public String getLoginPage() {
        String prefix = "";
        String application = getSSOApplication() + getSSOApplicationSuffix();
        String url = getSSOServer() + "/octopus/sso/authenticate";
        if (encryptionHandler != null) {
            prefix = "{" + url.length() + "}";
            String apiKey = getSSOApiKey();
            application = encryptionHandler.encryptData(application, apiKey);
            if (encryptionHandler.requiresApiKey()) {
                application = application + "&apiKey=" + apiKey;
            }
        }
        return prefix + url + "?application=" + application;
    }

    @ConfigEntry
    public String getSSOServer() {
        return ConfigResolver.getPropertyValue("SSO.server", "");
    }

    @ConfigEntry
    public String getSSOApplication() {
        return ConfigResolver.getPropertyValue("SSO.application", "");
    }

    @ConfigEntry
    public String getSSOApplicationSuffix() {
        return ConfigResolver.getPropertyValue("SSO.application.suffix", "");
    }

    @ConfigEntry
    public String getSSOApiKey() {
        return ConfigResolver.getPropertyValue("SSO.apiKey", "");
    }

    @ConfigEntry
    public String getSSOEndpointRoot() {
        return ConfigResolver.getPropertyValue("SSO.endpoint.root", "data");
    }

}
