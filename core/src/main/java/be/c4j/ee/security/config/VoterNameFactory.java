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

import be.c4j.ee.security.permission.PermissionLookup;
import be.c4j.ee.security.util.CDIUtil;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class VoterNameFactory {

    private static final String PERMISSION_VOTER = "PermissionVoter";

    private boolean initialized = false;
    private PermissionLookup permissionLookup;

    public String generatePermissionBeanName(String permissionNames) {
        checkDependencies();
        return generateName(permissionNames, PERMISSION_VOTER);
    }

    /**
     * This version can be used from within the extension and doesn't trigger the BeanManager (which isn't possible during execution of the extension.
     * This special version assumes that only one permission name is passed (so no , in parameter value)
     * This method assumes that a PermissionLookup will be available, which is ok since we have defined a NamedPermissionClass within configuration which makes a PermissionLookup required.
     *
     * @param permissionName
     * @return
     */
    public String generatePermissionBeanNameForExtension(String permissionName) {
        StringBuilder result = new StringBuilder();
        String voterName = transformName(permissionName.trim());
        result.append(voterName);
        result.append(PERMISSION_VOTER);
        return result.toString();
    }

    private void checkDependencies() {
        // We can't do this in a PostConstruct since we need the BeanManager which is still under construction at that point.
        if (!initialized) {
            // Find the optional permissionLookup
            permissionLookup = CDIUtil.getOptionalBean(PermissionLookup.class);
            initialized = true;
        }
    }

    private String generateName(String permissionNames, String voter) {
        String[] names = permissionNames.split(",");
        StringBuilder result = new StringBuilder();
        String voterName;
        for (String permissionName : names) {

            if (result.length() > 0) {
                result.append(", ");
            }
            if (permissionLookup != null && permissionLookup.containsPermission(permissionName.trim())) {
                voterName = transformName(permissionName.trim());
                result.append(voterName);
                result.append(voter);
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
        return result.toString();
    }

    public String generateRoleBeanName(String roleName) {
        return generateName(roleName, "RoleVoter");

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
