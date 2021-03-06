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

import be.c4j.ee.security.shiro.OctopusUserFilter;
import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
@PluginOrder(10)
public class JSFConfiguration implements ConfigurationPlugin {

    @Inject
    private OctopusJSFConfig config;

    @Override
    public void addConfiguration(Ini ini) {
        Ini.Section mainSection = ini.get(IniSecurityManagerFactory.MAIN_SECTION_NAME);
        mainSection.put("user", OctopusUserFilter.class.getName());
        mainSection.put("user.loginUrl", config.getLoginPage());


        mainSection.put("namedPermission.unauthorizedUrl", config.getUnauthorizedExceptionPage());
        mainSection.put("namedPermission1.unauthorizedUrl", config.getUnauthorizedExceptionPage());
        mainSection.put("np.unauthorizedUrl", config.getUnauthorizedExceptionPage());
        mainSection.put("np1.unauthorizedUrl", config.getUnauthorizedExceptionPage());
        mainSection.put("namedRole.unauthorizedUrl", config.getUnauthorizedExceptionPage());
        mainSection.put("namedRole1.unauthorizedUrl", config.getUnauthorizedExceptionPage());
        mainSection.put("nr.unauthorizedUrl", config.getUnauthorizedExceptionPage());
        mainSection.put("nr1.unauthorizedUrl", config.getUnauthorizedExceptionPage());
        mainSection.put("voter.unauthorizedUrl", config.getUnauthorizedExceptionPage());
        mainSection.put("userRequired.unauthorizedUrl", config.getUnauthorizedExceptionPage());

    }
}
