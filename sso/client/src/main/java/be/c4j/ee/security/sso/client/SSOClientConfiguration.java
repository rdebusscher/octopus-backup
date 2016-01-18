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
package be.c4j.ee.security.sso.client;

import be.c4j.ee.security.config.OctopusJSFConfig;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import org.apache.deltaspike.core.api.config.ConfigResolver;

import javax.enterprise.inject.Specializes;

/**
 *
 */
@Specializes
public class SSOClientConfiguration extends OctopusJSFConfig {
    @Override
    public String getLoginPage() {
        String result = "";
        return getSSOServer() + "/googleplus?application=" + getSSOApplication();
        // FIXME /googleplus is because we don't have the SSo server module yet
    }

    @ConfigEntry
    public String getSSOServer() {
        return ConfigResolver.getPropertyValue("SSO.server", "");
    }

    @ConfigEntry
    public String getSSOApplication() {
        return ConfigResolver.getPropertyValue("SSO.application", "");
    }

}
