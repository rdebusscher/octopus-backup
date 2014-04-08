package be.c4j.demo.security.demo.security;

import be.c4j.demo.security.UserInfo;
import be.c4j.demo.security.demo.model.Employee;
import be.c4j.demo.security.permission.DemoPermission;
import be.c4j.demo.security.permission.DemoPermissionCheck;
import be.c4j.ee.security.custom.AbstractGenericVoter;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import org.apache.myfaces.extensions.cdi.core.api.security.SecurityViolation;

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
    protected void checkPermission(InvocationContext invocationContext, Set<SecurityViolation> violations) {
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