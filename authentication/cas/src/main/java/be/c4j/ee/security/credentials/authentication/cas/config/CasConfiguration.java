/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.credentials.authentication.cas.config;

import be.c4j.ee.security.config.OctopusConfig;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.enterprise.inject.Specializes;

/**
 *
 */
@Specializes
public class CasConfiguration extends OctopusConfig {

    private String casService;

    @Override
    public String getLoginPage() {
        return "DYNAMIC CAS BASED";
    }

    @Override
    public String getLogoutPage() {
        String result;
        if (getCASSingleLogout()) {
            result = getSSOServer() + "/logout";
        } else {
            result = super.getLogoutPage();
        }
        return result;
    }

    @ConfigEntry
    public boolean getCASSingleLogout() {
        String singleLogout = ConfigResolver.getPropertyValue("CAS.single.logout", "true");
        return Boolean.valueOf(singleLogout);
    }

    @ConfigEntry
    public String getCASEmailProperty() {
        return ConfigResolver.getPropertyValue("CAS.property.email", "email");
    }

    @ConfigEntry
    public String getSSOServer() {
        return ConfigResolver.getPropertyValue("SSO.server", "");
    }

    @ConfigEntry
    public String getCASProtocol() {
        return ConfigResolver.getPropertyValue("CAS.protocol", "CAS"); // SAML should also be supported
    }

    @ConfigEntry(value = "Determined later on, see log entry")
    public String getCASService() {
        return casService;
    }

    public void setCasService(String casService) {
        this.casService = casService;
    }
}
