/*
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * /
 */
package be.c4j.ee.security.permission.filter;

import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.permission.PermissionLookup;
import be.c4j.ee.security.util.CDIUtil;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class NamedPermissionFilter extends AuthorizationFilter {

    private PermissionLookup<? extends NamedPermission> permissionLookup;

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws
            Exception {
        Subject subject = getSubject(request, response);
        String[] permissions = (String[]) mappedValue;
        checkLookup();

        boolean permitted = true;
        for(String permissionName : permissions) {
            if (!subject.isPermitted(permissionLookup.getPermission(permissionName))) {
                permitted = false;
            }
        }
        return permitted;
    }

    private void checkLookup() {
        // We can't do this in onFilterConfigSet as it is to soon.  Not available at that time
        if (permissionLookup == null) {
            permissionLookup = CDIUtil.getBeanManually(PermissionLookup.class);
        }
    }
}
