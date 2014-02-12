/*
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * /
 */
package be.c4j.ee.security.interceptor;

import be.c4j.ee.security.permission.CustomPermissionCheck;
import org.apache.myfaces.extensions.cdi.core.api.security.AbstractAccessDecisionVoter;
import org.apache.myfaces.extensions.cdi.core.api.security.SecurityViolation;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.authz.annotation.*;
import org.apache.shiro.subject.Subject;

import javax.annotation.security.PermitAll;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;
import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

@Interceptor
@AppSecured
public class AppSecurityInterceptor implements Serializable {

    private static final long serialVersionUID = 1L;

    @AroundInvoke
    public Object interceptShiroSecurity(InvocationContext context) throws Exception {
        Subject subject = SecurityUtils.getSubject();
        Class<?> classType = context.getTarget().getClass();
        Method method = context.getMethod();

        Set<?> annotations = getAllAnnotations(classType, method);
        if (!hasAnnotation(annotations, PermitAll.class)) {
            if (annotations.isEmpty()) {
                throw new UnauthenticatedException("No Authentication Info available");
            }

            if (!subject.isAuthenticated() && hasAnnotation(annotations, RequiresAuthentication.class)) {
                throw new UnauthenticatedException("Authentication required");
            }

            if (subject.getPrincipal() != null && hasAnnotation(annotations, RequiresGuest.class)) {
                throw new UnauthenticatedException("Guest required");
            }

            if (subject.getPrincipal() == null && hasAnnotation(annotations, RequiresUser.class)) {
                throw new UnauthenticatedException("User required");
            }

            RequiresRoles roles = getAnnotation(annotations, RequiresRoles.class);

            if (roles != null) {
                subject.checkRoles(Arrays.asList(roles.value()));
            }

            RequiresPermissions permissions = getAnnotation(annotations, RequiresPermissions.class);

            if (permissions != null) {
                subject.checkPermissions(permissions.value());
            }

            CustomPermissionCheck customCheck = getAnnotation(annotations, CustomPermissionCheck.class);

            if (customCheck != null) {
                Set<SecurityViolation> securityViolations = performCustomChecks(customCheck, context);
                if (!securityViolations.isEmpty()) {

                    throw new UnauthorizedException(getMessage(securityViolations));
                }
            }

        }

        return context.proceed();
    }

    private String getMessage(Set<SecurityViolation> securityViolations) {
        return securityViolations.iterator().next().getReason();
    }

    private Set<SecurityViolation> performCustomChecks(CustomPermissionCheck customCheck, InvocationContext invocationContext) {
        Set<SecurityViolation> result = new HashSet<SecurityViolation>();
        for ( Class<? extends AbstractAccessDecisionVoter> clsName :  customCheck.value()) {
            AbstractAccessDecisionVoter voter = CodiUtils.getContextualReferenceByClass(clsName);
            result.addAll(voter.checkPermission(invocationContext));
        }

        return result;
    }

    private static Set<?> getAllAnnotations(Class<?> someClassType, Method someMethod) {
        Set<Object> result = new HashSet<Object>();
        result.add(someMethod.getAnnotation(PermitAll.class));
        result.add(someMethod.getAnnotation(RequiresAuthentication.class));
        result.add(someMethod.getAnnotation(RequiresGuest.class));
        result.add(someMethod.getAnnotation(RequiresUser.class));
        result.add(someMethod.getAnnotation(RequiresRoles.class));
        result.add(someMethod.getAnnotation(RequiresPermissions.class));
        result.add(someMethod.getAnnotation(CustomPermissionCheck.class));

        result.add(getAnnotation(someClassType, PermitAll.class));
        result.add(getAnnotation(someClassType, RequiresAuthentication.class));
        result.add(getAnnotation(someClassType, RequiresGuest.class));
        result.add(getAnnotation(someClassType, RequiresUser.class));
        result.add(getAnnotation(someClassType, RequiresRoles.class));
        result.add(getAnnotation(someClassType, RequiresPermissions.class));

        result.remove(null);
        return result;
    }

    private static <A extends Annotation> boolean hasAnnotation(Set<?> annotations, Class<A> someAnnotation) {
        return getAnnotation(annotations, someAnnotation) != null;
    }

    private static <A extends Annotation> A getAnnotation(Class<?> someClass, Class<A> someAnnotation) {
        A result = null;
        if (someClass.isAnnotationPresent(someAnnotation)) {
            result = someClass.getAnnotation(someAnnotation);
        } else {
            if (someClass != Object.class) {
                result = getAnnotation(someClass.getSuperclass(), someAnnotation);
            }
        }
        return result;
    }

    private static <A extends Annotation> A getAnnotation(Set<?> annotations, Class<A> someAnnotation) {
        Object result = null;
        Iterator<?> iter = annotations.iterator();
        while (iter.hasNext() && result == null) {
            Object item = iter.next();
            if (someAnnotation.isAssignableFrom( item.getClass())) {
                result = item;
            }
        }
        return (A) result;
    }
}
