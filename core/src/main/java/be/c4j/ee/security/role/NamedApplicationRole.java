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
 *
 */
package be.c4j.ee.security.role;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import org.apache.shiro.authz.Permission;

/**
 *
 */
public class NamedApplicationRole implements Permission {

    private String roleName;

    public NamedApplicationRole(String roleName) {
        if (roleName == null || roleName.trim().length() == 0) {
            throw new OctopusConfigurationException("Role name can't be null or empty");
        }
        this.roleName = roleName;
    }

    @Override
    public boolean implies(Permission p) {
        // By default only supports comparisons with other NamedApplicationRole
        if (!(p instanceof NamedApplicationRole)) {
            return false;
        }
        NamedApplicationRole otherRole = (NamedApplicationRole) p;
        return roleName.equals(otherRole.roleName);
    }

    public String getRoleName() {
        return roleName;
    }
}
