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
package be.c4j.ee.security.exception;

import be.c4j.ee.security.OctopusInvocationContext;
import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.exception.violation.AuthorizationViolation;
import be.c4j.ee.security.exception.violation.BasicAuthorizationViolation;
import be.c4j.ee.security.exception.violation.MethodParameterTypeViolation;
import be.c4j.ee.security.exception.violation.OverloadingMethodParameterTypeViolation;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.role.NamedApplicationRole;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.apache.shiro.authz.Permission;

import javax.enterprise.context.ApplicationScoped;
import javax.interceptor.InvocationContext;
import java.util.Arrays;
import java.util.List;

/**
 *
 */
@ApplicationScoped
@PublicAPI
public class SecurityViolationInfoProducer {

    public String getViolationInfo(AccessDecisionVoterContext accessContext) {
        InvocationContext context = accessContext.getSource();
        return getExceptionPointInfo(context);
    }

    public String getViolationInfo(AccessDecisionVoterContext accessContext, SecurityViolation securityViolation) {
        AuthorizationViolation violation = defineCustomViolation(accessContext, securityViolation);
        if (violation == null) {
            InvocationContext context = accessContext.getSource();
            violation = new BasicAuthorizationViolation(securityViolation.getReason(), getExceptionPointInfo(context));
        }
        return violation.toString();
    }

    public String getViolationInfo(AccessDecisionVoterContext accessDecisionVoterContext, Permission violatedPermission) {
        AuthorizationViolation violation = defineCustomViolation(accessDecisionVoterContext, violatedPermission);
        if (violation == null) {
            InvocationContext invocationContext = accessDecisionVoterContext.getSource();
            violation = defineOctopusViolation(invocationContext, violatedPermission);
        }
        return violation.toString();
    }

    public AuthorizationViolation defineOctopusViolation(InvocationContext invocationContext, Permission violatedPermission) {
        String permissionInfo = null;
        if (violatedPermission instanceof NamedDomainPermission) {
            NamedDomainPermission namedPermission = (NamedDomainPermission) violatedPermission;
            permissionInfo = "Permission " + namedPermission.getName();
        }
        if (violatedPermission instanceof NamedApplicationRole) {
            NamedApplicationRole namedRole = (NamedApplicationRole) violatedPermission;
            permissionInfo = "Role " + namedRole.getRoleName();
        }
        return new BasicAuthorizationViolation(permissionInfo, getExceptionPointInfo(invocationContext));
    }

    protected AuthorizationViolation defineCustomViolation(AccessDecisionVoterContext accessDecisionVoterContext, Permission violatedPermission) {
        return null; // TODO Find out what the intention was. This doesn't seems very usefull
    }

    protected AuthorizationViolation defineCustomViolation(AccessDecisionVoterContext accessDecisionVoterContext, SecurityViolation violation) {
        return null; // TODO Find out what the intention was. This doesn't seems very usefull
    }

    protected String getExceptionPointInfo(InvocationContext invocationContext) {
        StringBuilder result = new StringBuilder();
        if (!(invocationContext instanceof OctopusInvocationContext)) {
            result.append("Class ").append(invocationContext.getTarget().getClass().getName());
            result.append("<br/>Method ").append(invocationContext.getMethod().getName());
            result.append("<br/>Parameters ");
            if (invocationContext.getParameters() != null) {
                for (Object parameter : invocationContext.getParameters()) {
                    if (parameter == null) {
                        result.append("<br/>").append(" ? = null");
                    } else {
                        result.append("<br/>").append(parameter.getClass().getName()).append(" = ").append(parameter);
                    }
                }
            }
        }
        return result.toString();
    }

    public String getWrongMethodSignatureInfo(InvocationContext invocationContext, List<Class<?>> missingParameterTypes) {
        return new MethodParameterTypeViolation(getExceptionPointInfo(invocationContext), missingParameterTypes).toString();
    }

    public String getWrongOverloadingMethodSignatureInfo(InvocationContext invocationContext, Class<?>... missingParameterTypes) {
        return new OverloadingMethodParameterTypeViolation(getExceptionPointInfo(invocationContext), Arrays.asList(missingParameterTypes)).toString();
    }

}
