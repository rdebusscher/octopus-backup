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
import be.c4j.demo.security.demo.service.EmployeeService;
import be.c4j.demo.security.permission.DemoPermission;
import be.c4j.demo.security.permission.DemoPermissionCheck;
import be.c4j.ee.security.custom.AbstractGenericVoter;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import org.apache.deltaspike.core.api.provider.BeanProvider;
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
public class EmployeeInfoVoter extends AbstractGenericVoter {

    @Inject
    private EmployeeService employeeService;

    @Inject
    @DemoPermissionCheck(DemoPermission.EMPLOYEE_READ_ALL)
    private GenericPermissionVoter employeeReadAllPermission;

    @Override
    protected void checkPermission(AccessDecisionVoterContext accessDecisionVoterContext, Set<SecurityViolation> violations) {

        boolean matchedParameter = false;

        InvocationContext invocationContext = accessDecisionVoterContext.getSource();

        if (verifyMethodHasParameterTypes(invocationContext, UserPrincipal.class)) {
            matchedParameter = true;
            checkEmployeeAccess(accessDecisionVoterContext, violations);
        }

        if (verifyMethodHasParameterTypes(invocationContext, Long.class)) {
            matchedParameter = true;
            checkEmployeeOrManagerAccess(accessDecisionVoterContext, violations);
        }


        if (!matchedParameter) {
            SecurityViolationInfoProducer infoProducer = BeanProvider.getContextualReference(SecurityViolationInfoProducer.class);
            violations.add(newSecurityViolation(infoProducer.getWrongOverloadingMethodSignatureInfo(invocationContext, UserPrincipal.class, Long.class)));


        }

    }

    private void checkEmployeeOrManagerAccess(AccessDecisionVoterContext accessContext, Set<SecurityViolation> violations) {
        InvocationContext invocationContext = accessContext.getSource();
        Long parameter = methodParameterCheckUtil.getAssignableParameter(invocationContext, Long.class);
        boolean allowed = false;

        if (userPrincipal.getUserInfo(UserInfo.EMPLOYEE_ID).equals(parameter)) {
            allowed = true;
        }

        if (!allowed) {
            if ( userPrincipal.getUserInfo(UserInfo.EMPLOYEE_ID).equals(employeeService.getManagerIdOfEmployee(parameter))) {
                allowed = true;
            }
        }

        if (!allowed && employeeReadAllPermission.verifyPermission()) {
            allowed = true;
        }

        if (!allowed) {
            SecurityViolationInfoProducer infoProducer = BeanProvider.getContextualReference(SecurityViolationInfoProducer.class);
            violations.add(newSecurityViolation(infoProducer.getViolationInfo(accessContext, newSecurityViolation("Employees can only view their own card or manager of the employee"))));
        }
    }

    private void checkEmployeeAccess(AccessDecisionVoterContext accessContext, Set<SecurityViolation> violations) {
        InvocationContext invocationContext = accessContext.getSource();
        UserPrincipal parameter = methodParameterCheckUtil.getAssignableParameter(invocationContext, UserPrincipal.class);
        if (!userPrincipal.equals(parameter)) {
            SecurityViolationInfoProducer infoProducer = BeanProvider.getContextualReference(SecurityViolationInfoProducer.class);
            violations.add(newSecurityViolation(infoProducer.getViolationInfo(accessContext, newSecurityViolation("Employees can only view their own card"))));
        }

    }
}
