package be.c4j.demo.security.demo.security;

import be.c4j.demo.security.UserInfo;
import be.c4j.demo.security.demo.service.EmployeeService;
import be.c4j.demo.security.permission.DemoPermission;
import be.c4j.demo.security.permission.DemoPermissionCheck;
import be.c4j.ee.security.custom.AbstractGenericVoter;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import org.apache.myfaces.extensions.cdi.core.api.security.SecurityViolation;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;

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
    protected void checkPermission(InvocationContext invocationContext, Set<SecurityViolation> violations) {

        boolean matchedParameter = false;

        if (verifyMethodHasParameterTypes(invocationContext, UserPrincipal.class)) {
            matchedParameter = true;
            checkEmployeeAccess(invocationContext, violations);
        }

        if (verifyMethodHasParameterTypes(invocationContext, Long.class)) {
            matchedParameter = true;
            checkEmployeeOrManagerAccess(invocationContext, violations);
        }


        if (!matchedParameter) {
            SecurityViolationInfoProducer infoProducer = CodiUtils.getContextualReferenceByClass(SecurityViolationInfoProducer.class);
            violations.add(newSecurityViolation(infoProducer.getWrongOverloadingMethodSignatureInfo(invocationContext, UserPrincipal.class, Long.class)));


        }

    }

    private void checkEmployeeOrManagerAccess(InvocationContext invocationContext, Set<SecurityViolation> violations) {
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
            SecurityViolationInfoProducer infoProducer = CodiUtils.getContextualReferenceByClass(SecurityViolationInfoProducer.class);
            violations.add(newSecurityViolation(infoProducer.getViolationInfo(invocationContext, newSecurityViolation("Employees can only view their own card or manager of the employee"))));
        }
    }

    private void checkEmployeeAccess(InvocationContext invocationContext, Set<SecurityViolation> violations) {
        UserPrincipal parameter = methodParameterCheckUtil.getAssignableParameter(invocationContext, UserPrincipal.class);
        if (!userPrincipal.equals(parameter)) {
            SecurityViolationInfoProducer infoProducer = CodiUtils.getContextualReferenceByClass(SecurityViolationInfoProducer.class);
            violations.add(newSecurityViolation(infoProducer.getViolationInfo(invocationContext, newSecurityViolation("Employees can only view their own card"))));
        }

    }
}
