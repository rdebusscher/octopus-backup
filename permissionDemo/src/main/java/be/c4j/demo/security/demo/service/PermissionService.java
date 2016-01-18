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
package be.c4j.demo.security.demo.service;

import be.c4j.demo.security.demo.model.HRAppPermission;
import be.c4j.demo.security.demo.model.Principal;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.NamedDomainPermission;

import javax.annotation.security.PermitAll;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 *
 */
@Stateless
@PermitAll // Because we need to have access to verify the credentials
public class PermissionService {

    @EJB
    private InMemoryDatabase database;

    public Principal getPrincipalByUserName(String userName) {
        return database.getPrincipalByUserName(userName);
    }


    public List<NamedDomainPermission> getAllPermissions() {
        List<HRAppPermission> permissionList = database.getPermissionList();
        List<NamedDomainPermission> result = new ArrayList<NamedDomainPermission>();
        for (HRAppPermission permission : permissionList) {
            result.add(new NamedDomainPermission(permission.getName(), permission.getDomain(), permission.getActions(), permission.getTarget()));
        }
        return result;
    }

    public Collection<HRAppPermission> getPermissionsForPrincipal(UserPrincipal primaryPrincipal) {
        return database.getPermissions(primaryPrincipal.getId());
    }
}

