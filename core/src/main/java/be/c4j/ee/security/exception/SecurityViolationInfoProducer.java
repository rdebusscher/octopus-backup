/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package be.c4j.ee.security.exception;

import be.c4j.ee.security.exception.violation.AuthorizationViolation;
import be.c4j.ee.security.exception.violation.BasicAuthorizationViolation;
import be.c4j.ee.security.exception.violation.MethodParameterTypeViolation;
import be.c4j.ee.security.exception.violation.OverloadingMethodParameterTypeViolation;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.role.NamedApplicationRole;
import be.c4j.ee.security.view.InvocationContextImpl;
import org.apache.myfaces.extensions.cdi.core.api.security.SecurityViolation;
import org.apache.shiro.authz.Permission;

import javax.enterprise.context.ApplicationScoped;
import javax.interceptor.InvocationContext;
import java.util.Arrays;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class SecurityViolationInfoProducer {

    public String getViolationInfo(InvocationContext invocationContext) {
        return getExceptionPointInfo(invocationContext);
    }

    public String getViolationInfo(InvocationContext invocationContext, SecurityViolation securityViolation) {
        AuthorizationViolation violation = defineCustomViolation(invocationContext, securityViolation);
        if (violation == null) {
            violation = new BasicAuthorizationViolation(securityViolation.getReason(), getExceptionPointInfo(invocationContext));
        }
        return violation.toString();
    }

    public String getViolationInfo(InvocationContext invocationContext, Permission violatedPermission) {
        AuthorizationViolation violation = defineCustomViolation(invocationContext, violatedPermission);
        if (violation == null) {
            violation = defineOctopusViolation(invocationContext, violatedPermission);
        }
        return violation.toString();
    }

    private AuthorizationViolation defineOctopusViolation(InvocationContext invocationContext, Permission violatedPermission) {
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

    protected AuthorizationViolation defineCustomViolation(InvocationContext invocationContext, Permission violatedPermission) {
        return null;
    }

    protected AuthorizationViolation defineCustomViolation(InvocationContext invocationContext, SecurityViolation violation) {
        return null;
    }

    protected String getExceptionPointInfo(InvocationContext invocationContext) {
        StringBuilder result = new StringBuilder();
        if (!(invocationContext instanceof InvocationContextImpl)) {
            result.append("Class ").append(invocationContext.getTarget().getClass().getName());
            result.append("<br/>Method ").append(invocationContext.getMethod().getName());
            result.append("<br/>Parameters ");
            if (invocationContext.getParameters() != null) {
                for (Object parameter : invocationContext.getParameters()) {
                    result.append("<br/>").append(parameter.getClass().getName()).append(" = ").append(parameter);
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