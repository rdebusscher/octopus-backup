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

    private String logoutPage;


    @Override
    public String getLoginPage() {

        return getSSOServer() + "/octopus/sso/authenticate";

    }

    public String getTokenEndpoint() {

        return getSSOServer() + "/octopus/sso/token";

    }

    public String getUserInfoEndpoint() {

        return getSSOServer() + "/data/octopus/sso/user";

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
    // FIXME Review the API key story :)
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

    @ConfigEntry(noLogging = true)
    public String getSSOClientSecret() {
        String ssoClientId = defineConfigValue("SSO.clientSecret");
        if (getSSOType() == SSOFlow.AUTHORIZATION_CODE && ssoClientId.trim().isEmpty()) {
            throw new OctopusConfigurationException("Value for {SSO.application}SSO.clientSecret parameter is empty");
        }
        return ssoClientId;
    }

    @ConfigEntry
    public SSOFlow getSSOType() {
        String ssoFlowParameter = defineConfigValue("SSO.flow");
        SSOFlow ssoFlow = SSOFlow.defineFlow(ssoFlowParameter);
        if (ssoFlow == null) {
            throw new OctopusConfigurationException("Value for {SSO.application}SSO.flow parameter is invalid. Must be 'id-token' or 'code'");
        }
        return ssoFlow;
    }

    @ConfigEntry
    public String getSSOScopes() {
        String result = defineConfigValue("SSO.scopes");
        if (result == null) {
            result = "";
        }
        return result;
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
