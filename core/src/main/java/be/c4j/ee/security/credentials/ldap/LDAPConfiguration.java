/*
 * Copyright 2014-2018 Rudy De Busscher
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
package be.c4j.ee.security.credentials.ldap;

import be.c4j.ee.security.config.AbstractOctopusConfig;
import be.c4j.ee.security.exception.OctopusConfigurationException;
import be.rubus.web.jerry.config.logging.ConfigEntry;
import be.rubus.web.jerry.config.logging.ModuleConfig;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.apache.shiro.util.StringUtils;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class LDAPConfiguration extends AbstractOctopusConfig implements ModuleConfig {

    @ConfigEntry
    public String getLDAPURL() {

        String result = ConfigResolver.getPropertyValue("ldap.url", null);
        if (!StringUtils.hasText(result)) {
            throw new OctopusConfigurationException("Value for configuration parameter 'ldap.url' is required");
        }
        return result;
    }

    @ConfigEntry
    public String getLDAPBindDN() {
        return ConfigResolver.getPropertyValue("ldap.bindDN", null);
    }

    @ConfigEntry(noLogging = true)
    public String getLDAPBindCredential() {
        return ConfigResolver.getPropertyValue("ldap.bindCredential", null);
    }

    @ConfigEntry
    public String getLDAPUserFilter() {
        String result = ConfigResolver.getPropertyValue("ldap.caller.filter", "(&(uid=%s)(|(objectclass=user)(objectclass=person)(objectclass=inetOrgPerson)(objectclass=organizationalPerson))(!(objectclass=computer)))");
        if (!StringUtils.hasText(result)) {
            throw new OctopusConfigurationException("Value for configuration parameter 'ldap.user.filter' is required (default is overridden!)");
        }
        return result;
    }

    @ConfigEntry
    public String getLDAPCallerNameAttribute() {
        return ConfigResolver.getPropertyValue("ldap.caller.name", "cn");
    }

    @ConfigEntry
    public String getLDAPCallerBaseSearch() {
        return ConfigResolver.getPropertyValue("ldap.caller.base", "");
    }

    @ConfigEntry
    public LDAPGroupsNeeded getLDAPGroupsLoaded() {
        String value = ConfigResolver.getPropertyValue("ldap.groups.loaded", "NO");
        LDAPGroupsNeeded result;
        try {
            result = LDAPGroupsNeeded.fromValue(value);
        } catch (IllegalArgumentException e) {
            throw new OctopusConfigurationException(String.format("Value for configuration parameter 'ldap.groups.loaded' is wrong. Allowed values are 'NO', 'GROUPS' and 'CALLER' but received '%s'", value));
        }
        return result;
    }

    @ConfigEntry
    public String getLDAPGroupFilter() {
        String result = ConfigResolver.getPropertyValue("ldap.groups.filter", "(&(member=%s)(|(objectclass=group)(objectclass=groupofnames)(objectclass=groupofuniquenames)))");
        if (!StringUtils.hasText(result)) {
            throw new OctopusConfigurationException("Value for configuration parameter 'ldap.userFilter' is required (default is overridden!)");
        }
        return result;
    }

    @ConfigEntry
    public String getLDAPGroupBaseSearch() {
        return ConfigResolver.getPropertyValue("ldap.groups.base", "");
    }

    @ConfigEntry
    public String getLDAPCallerMemberOfAttribute() {
        String result = ConfigResolver.getPropertyValue("ldap.caller.memberof", "memberOf");
        if (!StringUtils.hasText(result) && getLDAPGroupsLoaded() != LDAPGroupsNeeded.NO) {
            throw new OctopusConfigurationException("Value for configuration parameter 'ldap.caller.memberof' is required (default is overridden!)");
        }
        return result;
    }

    @ConfigEntry
    public String getLDAPGroupNameAttribute() {
        String result = ConfigResolver.getPropertyValue("ldap.group.name", "cn");
        if (!StringUtils.hasText(result) && getLDAPGroupsLoaded() != LDAPGroupsNeeded.NO) {
            throw new OctopusConfigurationException("Value for configuration parameter 'ldap.group.name' is required (default is overridden!)");
        }
        return result;
    }

}
