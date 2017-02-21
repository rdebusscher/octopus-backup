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
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.sso.SSOFlow;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.enterprise.inject.Specializes;

/**
 * FIXME documentation of the config parameters !!
 */
@Specializes
public class OctopusSSOClientConfiguration extends OctopusJSFConfig {

    private String loginPage;
    private String logoutPage;


    @Override
    public String getLoginPage() {
        if (loginPage == null) {

            String url = getSSOServer() + "/octopus/sso/authenticate";

            loginPage = url + "?client_id=" + getSSOClientId() + "&response_type=" + getSSOType().getResponseType();

        }
        return loginPage;
    }

    @Override
    public String getLogoutPage() {
        if (logoutPage == null) {

            logoutPage = getSSOServer() + "/octopus/sso/logout?client_id=" + getSSOClientId();
        }
        return logoutPage;
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

    @ConfigEntry
    public String getSSOClientId() {
        String ssoClientId = defineConfigValue("SSO.clientId");
        if (ssoClientId.trim().isEmpty()) {
            throw new OctopusConfigurationException("Value for {SSO.application}SSO.clientId parameter is empty");
        }
        return ssoClientId;
    }

    @ConfigEntry
    public SSOFlow getSSOType() {
        SSOFlow ssoFlow = SSOFlow.defineFlow(ConfigResolver.getPropertyValue("SSO.flow", ""));
        if (ssoFlow == null) {
            throw new OctopusConfigurationException("Value for SSO.flow parameter is invalid. Must be 'token' or 'code'");
        }
        return ssoFlow;
    }

    private String defineConfigValue(String configParameter) {
        String configKeyPrefix = getSSOApplication() + getSSOApplicationSuffix();
        String result = ConfigResolver.getPropertyValue(configKeyPrefix + '.' + configParameter, "");
        if (result.trim().isEmpty()) {
            result = ConfigResolver.getPropertyValue(configParameter, "");
        }
        return result;
    }

    @ConfigEntry
    public String getAccessPermission() {
        return ConfigResolver.getPropertyValue("SSO.application.permission.access", "");
    }

}
