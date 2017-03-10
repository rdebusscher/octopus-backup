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
package be.c4j.ee.security.role.filter;

import be.c4j.ee.security.role.NamedApplicationRole;
import be.c4j.ee.security.role.NamedRole;
import be.c4j.ee.security.role.RoleLookup;
import be.c4j.ee.security.util.CDIUtil;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 *
 */
public class NamedRoleOneFilter extends AuthorizationFilter {

    private RoleLookup<? extends NamedRole> roleLookup;

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws
            Exception {
        Subject subject = getSubject(request, response);
        String[] roles = (String[]) mappedValue;
        checkLookup();

        boolean permitted = false;
        for (String role : roles) {
            if (subject.isPermitted(getRolePermission(role))) {
                permitted = true;
            }
        }
        return permitted;
    }

    private NamedApplicationRole getRolePermission(String role) {
        NamedApplicationRole result;
        checkLookup();

        if (roleLookup == null) {
            // TODO Should we cache these instances somewhere? (memory improvement)
            result = new NamedApplicationRole(role);
        } else {
            result = roleLookup.getRole(role);
        }
        return result;
    }

    private void checkLookup() {
        // We can't do this in onFilterConfigSet as it is to soon.  Not available at that time
        if (roleLookup == null) {
            roleLookup = CDIUtil.getOptionalBean(RoleLookup.class);
        }
    }
}
