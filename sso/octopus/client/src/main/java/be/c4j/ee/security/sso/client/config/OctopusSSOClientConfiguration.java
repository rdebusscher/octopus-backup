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

import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.c4j.ee.security.sso.SSOFlow;
import be.c4j.ee.security.util.StringUtil;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import com.nimbusds.jose.util.Base64;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.enterprise.inject.Specializes;
import javax.inject.Inject;

/**
 *
 */
@Specializes
@PublicAPI
public class OctopusSSOClientConfiguration extends OctopusJSFConfig {

    private String logoutPage;

    @Inject
    private StringUtil stringUtil;

    @Override
    public String getLoginPage() {

        return getOctopusSSOServer() + "/octopus/sso/authenticate";

    }

    @Override
    public String getLogoutPage() {
        if (logoutPage == null) {

            logoutPage = getOctopusSSOServer() + "/octopus/sso/logout";
        }
        return logoutPage;
    }

    @ConfigEntry
    public String getOctopusSSOServer() {
        String result = ConfigResolver.getPropertyValue("SSO.octopus.server");
        if (stringUtil.isEmpty(result)) {
            throw new OctopusConfigurationException("Value for SSO.octopus.server parameter is empty.");
        }
        return result;

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
    public String getSSOClientId() {
        String ssoClientId = defineConfigValue("SSO.clientId");
        if (stringUtil.isEmpty(ssoClientId)) {
            throw new OctopusConfigurationException("Value for {SSO.application}SSO.clientId parameter is empty");
        }
        return ssoClientId;
    }

    @ConfigEntry(noLogging = true)
    public byte[] getSSOClientSecret() {
        String ssoClientSecret = defineConfigValue("SSO.clientSecret");
        if (getSSOType() == SSOFlow.AUTHORIZATION_CODE && stringUtil.isEmpty(ssoClientSecret)) {
            throw new OctopusConfigurationException("Value for {SSO.application}SSO.clientSecret parameter is empty");
        }
        if (ssoClientSecret != null && !ssoClientSecret.trim().isEmpty()) {
            byte[] result = new Base64(ssoClientSecret).decode();
            if (result.length < 32) {
                throw new OctopusConfigurationException("value for {SSO.application}SSO.clientSecret must be at least 32 byte (256 bit)");
            }
            return result;
        } else {
            return new byte[0];
        }
    }

    @ConfigEntry(noLogging = true)
    public byte[] getSSOIdTokenSecret() {
        String tokenSecret = defineConfigValue("SSO.idTokenSecret");
        if (stringUtil.isEmpty(tokenSecret)) {
            throw new OctopusConfigurationException("Value for {SSO.application}SSO.idTokenSecret parameter is empty");
        }

        byte[] result = new Base64(tokenSecret).decode();

        if (result.length < 32) {
            throw new OctopusConfigurationException("value for {SSO.application}SSO.idTokenSecret must be at least 32 byte (256 bit)");
        }
        return result;
    }

    @ConfigEntry
    public SSOFlow getSSOType() {
        String ssoFlowParameter = defineConfigValue("SSO.flow");
        SSOFlow ssoFlow = SSOFlow.defineFlow(ssoFlowParameter);
        if (ssoFlow == null) {
            throw new OctopusConfigurationException("Value for {SSO.application}SSO.flow parameter is invalid. Must be 'token' or 'code'");
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
