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
package be.c4j.ee.security.config;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class VoterNameFactory {

    public String generatePermissionBeanName(String permissionNames) {
        return generateName(permissionNames, "PermissionVoter");

    }

    private String generateName(String permissionNames, String voter) {
        String[] names = permissionNames.split(",");
        StringBuilder result = new StringBuilder();
        for (String permissionName : names) {
            if (result.length() > 0) {
                result.append(", ");
            }
            result.append(transformName(permissionName));
            result.append(voter);
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
