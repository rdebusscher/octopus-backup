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
package be.c4j.ee.security.authentication.cas;

import be.c4j.ee.security.config.AbstractOctopusConfig;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import org.apache.deltaspike.core.api.config.ConfigResolver;

/**
 *
 *
 */
public class CasSEConfiguration extends AbstractOctopusConfig {

    private String casService;

    public String getCASEmailProperty() {
        return ConfigResolver.getPropertyValue("CAS.property.email", "email");
    }

    public String getSSOServer() {
        return ConfigResolver.getPropertyValue("SSO.server", "");
    }

    public CASProtocol getCASProtocol() {

        String casProtocol = ConfigResolver.getPropertyValue("CAS.protocol", "CAS");
        // SAML should also be supported, but not tested for the moment.

        CASProtocol result = CASProtocol.fromValue(casProtocol);
        if (result == null) {
            throw new OctopusConfigurationException(String.format("Invalid value for parameter CAS.protocol specified : %s (CAS or SMAL allowed)", casProtocol));
        }
        return result;
    }

    public String getCASService() {
        if (casService == null) {
            casService = ConfigResolver.getPropertyValue("CAS.service");
        }
        return casService;
    }

    public void setCasService(String casService) {
        this.casService = casService;
    }

    public static void prepareConfiguration() {
        // FIXME Document
        new CasSEConfiguration().defineConfigurationSources();
    }
}
