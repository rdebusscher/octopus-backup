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

import be.c4j.ee.security.permission.PermissionLookup;
import be.c4j.ee.security.role.NamedApplicationRole;
import be.c4j.ee.security.role.RoleLookup;
import be.c4j.ee.security.util.CDIUtil;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class VoterNameFactory {

    private boolean initialized = false;
    private PermissionLookup permissionLookup;
    private RoleLookup roleLookup;
    private OctopusConfig octopusConfig;

    public String generatePermissionBeanName(String permissionNames) {
        checkDependencies();
        return generateName(permissionNames, octopusConfig.getPermissionVoterSuffix(), false);
    }

    /**
     * This version can be used from within the extension and doesn't trigger the BeanManager (which isn't possible during execution of the extension.
     * This special version assumes that only one permission name (or role name) is passed (so no , in parameter value)
     * This method assumes that a PermissionLookup will be available, which is ok since we have defined a NamedPermissionClass within configuration which makes a PermissionLookup required.
     * (in other words : Method is called from extension and only when we have NamedPermissionClass, we are calling this method. And NamedPermissionClass requires  PermissionLookup)
     *
     * @param name
     * @return
     */
    public String generateBeanNameForExtension(String name, String voterSuffix) {
        StringBuilder result = new StringBuilder();
        String voterName = transformName(name.trim());
        result.append(voterName);
        result.append(voterSuffix);
        return result.toString();
    }

    private void checkDependencies() {
        // We can't do this in a PostConstruct since we need the BeanManager which is still under construction at that point.
        if (!initialized) {
            // Find the optional permissionLookup
            permissionLookup = CDIUtil.getOptionalBean(PermissionLookup.class);
            roleLookup = CDIUtil.getOptionalBean(RoleLookup.class);

            octopusConfig = BeanProvider.getContextualReference(OctopusConfig.class);

            initialized = true;
        }
    }

    private String generateName(String permissionNames, String voterSuffix, boolean role) {
        String[] names = permissionNames.split(",");
        StringBuilder result = new StringBuilder();
        for (String permissionName : names) {

            if (result.length() > 0) {
                result.append(", ");
            }

            if (role) {
                handleRole(result, permissionName, voterSuffix);
            } else {
                handlePermission(result, permissionName, voterSuffix);
            }
        }
        return result.toString();
    }

    private void handlePermission(StringBuilder result, String permissionName, String voterSuffix) {
        String voterName;
        if (permissionLookup != null && permissionLookup.containsPermission(permissionName.trim())) {
            voterName = transformName(permissionName.trim());
            result.append(voterName);
            result.append(voterSuffix);
        } else {
            if (permissionName.contains(":")) {
                // We have a fully defined permission name like octopus:test:*
                result.append(permissionName.trim());
            } else {
                // We have a named Permission octopusTest, which is not an enum value but String based.
                //The : in front will flag this situation later on.
                result.append(':').append(permissionName.trim());
            }
        }
    }

    private void handleRole(StringBuilder result, String roleName, String voterSuffix) {
        String voterName;
        NamedApplicationRole namedRole = null;
        if (roleLookup != null) {
            namedRole = roleLookup.getRole(roleName.trim());
        }
        if (namedRole != null) {
            // Role is explicitly mapped and thus bean is created by the extension.
            // TODO Verify, what should we use as name roleName or namedRole properties. Verify with Extension and IntegrationTest
            voterName = transformName(roleName.trim());
            result.append(voterName);
            result.append(voterSuffix);
        } else {
            // We have a named role which is not explicitly defined. Use the name as such
            result.append("::").append(roleName.trim());

        }
    }

    public String generateRoleBeanName(String roleName) {
        checkDependencies();
        return generateName(roleName, octopusConfig.getRoleVoterSuffix(), true);
    }

    private String transformName(String roleName) {
        String[] parts = roleName.toLowerCase().split("_");
        if (parts.length > 1) {
            for (int i = 1; i < parts.length; i++) {
                parts[i] = capitalize(parts[i]);
            }
        }
        StringBuilder result = new StringBuilder();
        for (String part : parts) {
            result.append(part);
        }
        return result.toString();
    }

    private String capitalize(String line) {
        return Character.toUpperCase(line.charAt(0)) + line.substring(1);
    }
}
