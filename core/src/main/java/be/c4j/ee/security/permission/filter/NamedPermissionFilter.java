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
package be.c4j.ee.security.permission.filter;

import be.c4j.ee.security.permission.OctopusPermissionResolver;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class NamedPermissionFilter extends AuthorizationFilter implements Initializable {

    private OctopusPermissionResolver permissionResolver;

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws
            Exception {
        Subject subject = getSubject(request, response);
        String[] permissions = (String[]) mappedValue;  // TODO What does Shiro give as as we don't specify value like np[]

        boolean permitted = true;
        for (String permissionName : permissions) {

            Permission permission = permissionResolver.resolvePermission(permissionName);
            if (!subject.isPermitted(permission)) {
                permitted = false;
            }
        }
        return permitted;
    }

    @Override
    public void init() throws ShiroException {
        permissionResolver = BeanProvider.getContextualReference(OctopusPermissionResolver.class);
        permissionResolver.init();
    }

}
