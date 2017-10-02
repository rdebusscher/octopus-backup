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
package be.c4j.ee.security.credentials.authentication.oauth2;

import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.config.OctopusJSFConfig;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.enterprise.inject.Specializes;
import javax.inject.Inject;

/**
 *
 */
@Specializes
@PublicAPI
public class OAuth2Configuration extends OctopusJSFConfig {

    @Inject
    private OAuth2ProviderMetaDataControl oAuth2ProviderMetaDataControl;

    @Override
    public String getLoginPage() {
        return "DYNAMIC OAUTH2 BASED";
    }

    @ConfigEntry(noLogging = true)
    public String getClientId() {
        return defineConfigValue("OAuth2.clientId");
    }

    private String defineConfigValue(String configParameter) {
        StringBuilder result = new StringBuilder();
        if (oAuth2ProviderMetaDataControl.getProviderInfos().size() < 2) {
            result.append(ConfigResolver.getPropertyValue(configParameter, ""));
        } else {
            String userProviderSelection = getUserProviderSelection();
            if (userProviderSelection == null || userProviderSelection.isEmpty()) {
                for (OAuth2ProviderMetaData oAuth2ProviderMetaData : oAuth2ProviderMetaDataControl.getProviderInfos()) {
                    result.append(oAuth2ProviderMetaData.getName()).append(" : ");
                    result.append(ConfigResolver.getPropertyValue(oAuth2ProviderMetaData.getName() + '.' + configParameter, ""));
                    result.append("\n");
                }
            } else {
                result.append(ConfigResolver.getPropertyValue(userProviderSelection + '.' + configParameter, ""));
            }
        }
        return result.toString();
    }

    @ConfigEntry(noLogging = true)
    public String getClientSecret() {
        return defineConfigValue("OAuth2.clientSecret");
    }

    @ConfigEntry
    public String getOAuth2ProviderSelectionPage() {
        return ConfigResolver.getPropertyValue("OAuth2.provider.selectionPage", "/login.xhtml");
    }

    @ConfigEntry
    public String getOAuth2Scopes() {
        return ConfigResolver.getPropertyValue("OAuth2.scopes", "");
    }

    private String getUserProviderSelection() {
        try {
            DefaultOauth2ServletInfo defaultOauth2ServletInfo = BeanProvider.getContextualReference(DefaultOauth2ServletInfo.class);
            return defaultOauth2ServletInfo.getUserProviderSelection();
        } catch (Exception e) {
            // At startup logging, the session scope is not active yet and thus we get an exception here.
            // return null to indicate that the user hasn't made a choice yet.
            return null;

        }
    }
}
