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
package be.c4j.ee.security.authentication.octopus;

import be.c4j.ee.security.config.AbstractOctopusConfig;
import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import com.nimbusds.jose.util.Base64;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */

public class OctopusSEConfiguration extends AbstractOctopusConfig {

    private List<Debug> debugValues;

    public String getSSOApplication() {
        return ConfigResolver.getPropertyValue("SSO.application", "");
    }

    public String getSSOApplicationSuffix() {
        return ConfigResolver.getPropertyValue("SSO.application.suffix", "");
    }

    public String getOctopusSSOServer() {
        String result = ConfigResolver.getPropertyValue("SSO.octopus.server");
        if (result == null || result.trim().isEmpty()) {
            throw new OctopusConfigurationException("Value for SSO.octopus.server parameter is empty.");
        }
        return result;
    }

    public String getUserInfoEndpoint() {
        return getOctopusSSOServer() + "/" + getSSOEndpointRoot() + "/octopus/sso/user";

    }

    public String getTokenEndpoint() {

        return getOctopusSSOServer() + "/octopus/sso/token";

    }

    public String getSSOEndpointRoot() {
        String ssoEndPointRoot = ConfigResolver.getPropertyValue("SSO.endpoint.root", "data");
        return ssoEndPointRoot.replaceAll("^/+", "").replaceAll("/+$", "");
    }

    public String getSSOClientId() {
        String ssoClientId = defineConfigValue("SSO.clientId");
        if (ssoClientId.trim().isEmpty()) {
            throw new OctopusConfigurationException("Value for {SSO.application}SSO.clientId parameter is empty");
        }
        return ssoClientId;
    }

    public byte[] getSSOClientSecret() {
        String ssoClientSecret = defineConfigValue("SSO.clientSecret");
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

    public byte[] getSSOIdTokenSecret() {
        String tokenSecret = defineConfigValue("SSO.idTokenSecret");
        if (tokenSecret.trim().isEmpty()) {
            throw new OctopusConfigurationException("Value for {SSO.application}SSO.idTokenSecret parameter is empty");
        }

        byte[] result = new Base64(tokenSecret).decode();

        if (result.length < 32) {
            throw new OctopusConfigurationException("value for {SSO.application}SSO.idTokenSecret must be at least 32 byte (256 bit)");
        }
        return result;
    }

    public String getSSOScopes() {
        String result = defineConfigValue("SSO.scopes");
        if (result == null) {
            result = "";
        }
        return result;
    }

    public List<Debug> showDebugFor() {
        if (debugValues == null) {
            // TODO Do we need to make this thread-safe?
            List<Debug> result = new ArrayList<Debug>();
            String value = ConfigResolver.getPropertyValue("show.debug", "");
            String[] parts = value.split(",");
            for (String part : parts) {
                String code = part.trim();
                if (code.length() > 0) {
                    try {
                        Debug debug = Debug.valueOf(code);
                        result.add(debug);
                    } catch (IllegalArgumentException e) {
                        LOGGER.error("Value defined in the show.debug property unknown ", part);
                    }
                }
            }
            debugValues = result;
        }
        return debugValues;
    }

    private String defineConfigValue(String configParameter) {
        String configKeyPrefix = getSSOApplication() + getSSOApplicationSuffix();
        String result = ConfigResolver.getPropertyValue(configKeyPrefix + '.' + configParameter, "");
        if (result.trim().isEmpty()) {
            result = ConfigResolver.getPropertyValue(configParameter, "");
        }
        return result;
    }

    public static void prepareConfiguration() {
        // FIXME Document
        new OctopusSEConfiguration().defineConfigurationSources();
    }
}
