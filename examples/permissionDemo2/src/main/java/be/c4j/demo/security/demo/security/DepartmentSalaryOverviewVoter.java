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
package be.c4j.demo.security.demo.security;

import be.c4j.demo.security.UserInfo;
import be.c4j.demo.security.demo.model.dto.DepartmentWithSalaryTotal;
import be.c4j.ee.security.custom.AbstractGenericVoter;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.realm.OctopusPermissions;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import javax.inject.Inject;
import javax.inject.Named;
import javax.interceptor.InvocationContext;
import java.util.Set;

/**
 *
 */
@Named
public class DepartmentSalaryOverviewVoter extends AbstractGenericVoter {

    @Inject
    @OctopusPermissions("DepartmentSalaryAll")
    private GenericPermissionVoter permissionSalaryAll;

    @Inject
    @OctopusPermissions("DepartmentSalaryManager")
    private GenericPermissionVoter permissionSalaryManager;

    @Override
    protected void checkPermission(AccessDecisionVoterContext accessDecisionVoterContext, Set<SecurityViolation> violations) {

        boolean allowed = permissionSalaryAll.verifyPermission();
        if (!allowed) {
            if (permissionSalaryManager.verifyPermission()) {
// TODO Check op parameter
                InvocationContext invocationContext = accessDecisionVoterContext.getSource();
                DepartmentWithSalaryTotal department = methodParameterCheckUtil.getAssignableParameter(invocationContext, DepartmentWithSalaryTotal.class);


                if (department.getId().equals(userPrincipal.getUserInfo(UserInfo.DEPARTMENT_ID.name()))) {
                    allowed = true;
                }
            }
        }
        if (!allowed) {
            violations.add(newSecurityViolation("Department salary not readable"));
        }
    }

}
