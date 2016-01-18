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
import java.util.Scanner;
import java.util.Set;

/**
 *
 */
@Named
public class EmployeeSalaryUpdateVoter extends AbstractGenericVoter {

    @Inject
    @DemoPermissionCheck(DemoPermission.EMPLOYEE_UPDATE_SALARY)
    private GenericPermissionVoter permissionEmployeeUpdateSalary;

    @Override
    protected void checkPermission(AccessDecisionVoterContext accessDecisionVoterContext, Set<SecurityViolation> violations) {
        boolean allowed = false;

        InvocationContext invocationContext = accessDecisionVoterContext.getSource();
        if (hasServletRequestInfo(invocationContext)) {
            String employeeId = getURLRequestParameter(invocationContext, "employeeId");
            allowed = checkSalaryUpdateAllowed(asLong(employeeId));
        }

        if (!allowed && verifyMethodHasParameterTypes(invocationContext, Long.class)) {

            Long employeeId = methodParameterCheckUtil.getAssignableParameter(invocationContext, Long.class);
            allowed = checkSalaryUpdateAllowed(employeeId);
        }

        if (!allowed && verifyMethodHasParameterTypes(invocationContext, Employee.class)) {
            Employee employee = methodParameterCheckUtil.getAssignableParameter(invocationContext, Employee.class);
            allowed = checkSalaryUpdateAllowed(employee.getId());
        }

        if (!allowed) {
            violations.add(newSecurityViolation("You are not allowed to update your own salary"));
        }
    }

    private boolean checkSalaryUpdateAllowed(Long employeeId) {
        return !userPrincipal.getUserInfo(UserInfo.EMPLOYEE_ID).equals(employeeId) && employeeId != null;
    }

    private Long asLong(String value) {
        Long result = null;

        if (value != null) {
            Scanner scanner = new Scanner(value);
            if (scanner.hasNextLong()) {
                result = scanner.nextLong();
            }
        }
        return result;
    }
}
