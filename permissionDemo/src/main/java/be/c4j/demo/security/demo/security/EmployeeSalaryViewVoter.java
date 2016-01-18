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
package be.c4j.demo.security.demo.security;

import be.c4j.demo.security.UserInfo;
import be.c4j.demo.security.demo.model.Employee;
import be.c4j.demo.security.permission.DemoPermission;
import be.c4j.demo.security.permission.DemoPermissionCheck;
import be.c4j.ee.security.custom.AbstractGenericVoter;
import be.c4j.ee.security.permission.GenericPermissionVoter;
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
public class EmployeeSalaryViewVoter extends AbstractGenericVoter {

    @Inject
    @DemoPermissionCheck(DemoPermission.DEPARTMENT_SALARY_ALL)
    private GenericPermissionVoter permissionSalaryAll;

    @Inject
    @DemoPermissionCheck(DemoPermission.DEPARTMENT_SALARY_MANAGER)
    private GenericPermissionVoter permissionSalaryManager;

    @Override
    protected void checkPermission(AccessDecisionVoterContext accessDecisionVoterContext, Set<SecurityViolation> violations) {
        InvocationContext invocationContext = accessDecisionVoterContext.getSource();
        checkMethodHasParameterTypes(violations, invocationContext, Employee.class);

        if (violations.isEmpty()) {
            Employee parameter = methodParameterCheckUtil.getAssignableParameter(invocationContext, Employee.class);
            boolean result = permissionSalaryAll.verifyPermission();
            if (!result) {
                result = userPrincipal.getUserInfo(UserInfo.EMPLOYEE_ID).equals(parameter.getId());
            }
            if (!result && parameter.getManager() != null) {
                result = userPrincipal.getUserInfo(UserInfo.EMPLOYEE_ID).equals(parameter.getManager().getId());
            }

            if (!result) {
                violations.add(newSecurityViolation("Employee Salary not visible"));
            }
        }

    }
}