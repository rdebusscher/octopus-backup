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
package be.c4j.ee.security.permission;

import be.c4j.ee.security.util.CDIUtil;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.WildcardPermissionResolver;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class OctopusPermissionResolver extends WildcardPermissionResolver {

    private PermissionLookup permissionLookup;

    private StringPermissionLookup stringLookup;

    @PostConstruct
    public void init() {
        permissionLookup = CDIUtil.getOptionalBean(PermissionLookup.class);
        stringLookup = CDIUtil.getOptionalBean(StringPermissionLookup.class);
    }

    @Override
    public Permission resolvePermission(String permissionString) {
        Permission permission;
        if (permissionLookup == null && stringLookup == null) {
            if (permissionString.contains(":")) {
                permission = super.resolvePermission(permissionString);
            } else {
                permission = super.resolvePermission(permissionString + ":*:*");
            }
        } else {
            if (permissionLookup != null) {
                permission = permissionLookup.getPermission(permissionString);
            } else {
                permission = stringLookup.getPermission(permissionString);
            }
        }
        return permission;
    }
}
