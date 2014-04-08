package be.c4j.demo.security.demo.security;

import be.c4j.demo.security.UserInfo;
import be.c4j.demo.security.demo.model.dto.DepartmentWithSalaryTotal;
import be.c4j.demo.security.permission.DemoPermission;
import be.c4j.demo.security.permission.DemoPermissionCheck;
import be.c4j.ee.security.custom.AbstractGenericVoter;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import org.apache.myfaces.extensions.cdi.core.api.security.AbstractAccessDecisionVoter;
import org.apache.myfaces.extensions.cdi.core.api.security.AbstractDecisionVoter;
import org.apache.myfaces.extensions.cdi.core.api.security.SecurityViolation;

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
    @DemoPermissionCheck(DemoPermission.DEPARTMENT_SALARY_ALL)
    private GenericPermissionVoter permissionSalaryAll;

    @Inject
    @DemoPermissionCheck(DemoPermission.DEPARTMENT_SALARY_MANAGER)
    private GenericPermissionVoter permissionSalaryManager;

    @Override
    protected void checkPermission(InvocationContext invocationContext, Set<SecurityViolation> violations) {

        boolean allowed = permissionSalaryAll.verifyPermission();
        if (!allowed) {
            if (permissionSalaryManager.verifyPermission())  {
// TODO Check op parameter
                DepartmentWithSalaryTotal department = methodParameterCheckUtil.getAssignableParameter(invocationContext, DepartmentWithSalaryTotal.class);


                if (department.getId().equals(userPrincipal.getUserInfo(UserInfo.DEPARTMENT_ID))) {
                    allowed = true;
                }
            }
        }
        if (!allowed) {
            violations.add(newSecurityViolation("Department salary not readable"));
        }
    }
}
