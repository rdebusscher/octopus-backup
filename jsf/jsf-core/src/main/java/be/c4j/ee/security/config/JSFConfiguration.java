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

        // FIXME For Issue 83, We need to add here the other filters
        /*
        namedPermission = be.c4j.ee.security.permission.filter.NamedPermissionFilter
        namedPermission1 = be.c4j.ee.security.permission.filter.NamedPermissionOneFilter
        np = be.c4j.ee.security.permission.filter.NamedPermissionFilter
        np1 = be.c4j.ee.security.permission.filter.NamedPermissionOneFilter
        namedRole = be.c4j.ee.security.role.filter.NamedRoleFilter
        namedRole1 = be.c4j.ee.security.role.filter.NamedRoleOneFilter
        nr = be.c4j.ee.security.role.filter.NamedRoleFilter
        nr1 = be.c4j.ee.security.role.filter.NamedRoleOneFilter
        voter = be.c4j.ee.security.custom.filter.CustomVoterFilter
         */

    }
}
