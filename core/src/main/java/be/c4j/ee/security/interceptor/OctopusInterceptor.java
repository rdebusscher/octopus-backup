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

import be.c4j.ee.security.CustomAccessDecissionVoterContext;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.custom.CustomVoterCheck;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.realm.OctopusRealm;
import be.c4j.ee.security.realm.OnlyDuringAuthentication;
import be.c4j.ee.security.role.NamedRole;
import be.c4j.ee.security.util.AnnotationUtil;
import be.c4j.ee.security.util.CDIUtil;
import org.apache.deltaspike.core.api.provider.BeanManagerProvider;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.deltaspike.security.api.authorization.AbstractAccessDecisionVoter;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.*;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;

import javax.annotation.security.PermitAll;
import javax.enterprise.inject.spi.BeanManager;
import javax.inject.Inject;
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
@OctopusInterceptorBinding
public class OctopusInterceptor implements Serializable {

    private static final long serialVersionUID = 1L;

    @Inject
    private OctopusConfig config;

    @Inject
    private VoterNameFactory nameFactory;

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    //@PostConstruct With Weld 2.X, there seems to be an issue
    public void init(InvocationContext context) {
        if (config == null) {
            // WLS12C doesn't inject into interceptors
            config = BeanProvider.getContextualReference(OctopusConfig.class);
            nameFactory = BeanProvider.getContextualReference(VoterNameFactory.class);
            infoProducer = BeanProvider.getContextualReference(SecurityViolationInfoProducer.class);
        }
    }

    @AroundInvoke
    public Object interceptShiroSecurity(InvocationContext context) throws Exception {
        init(context);  // Since @PostConstruct isn't allowed in Weld 2.x
        Subject subject = SecurityUtils.getSubject();
        Class<?> classType = context.getTarget().getClass();
        Method method = context.getMethod();

        AccessDecisionVoterContext accessContext = new CustomAccessDecissionVoterContext(context);

        Set<?> annotations = getAllAnnotations(classType, method);
        if (!hasAnnotation(annotations, PermitAll.class)) {
            if (annotations.isEmpty()) {
                throw new OctopusUnauthorizedException("No Authorization requirements available", infoProducer.getViolationInfo(accessContext));
            }

            if (hasAnnotation(annotations, OnlyDuringAuthentication.class)) {
                if (subject.getPrincipal() != null || !(ThreadContext.get(OctopusRealm.IN_AUTHENTICATION_FLAG) instanceof OctopusRealm.InAuthentication)) {
                    throw new OctopusUnauthorizedException("Execution of method only allowed during authentication process", infoProducer.getViolationInfo(accessContext));
                }
            }
            if (!subject.isAuthenticated() && hasAnnotation(annotations, RequiresAuthentication.class)) {
                throw new OctopusUnauthorizedException("Authentication required", infoProducer.getViolationInfo(accessContext));
            }

            if (subject.getPrincipal() != null && hasAnnotation(annotations, RequiresGuest.class)) {
                throw new OctopusUnauthorizedException("Guest required", infoProducer.getViolationInfo(accessContext));
            }

            if (subject.getPrincipal() == null && hasAnnotation(annotations, RequiresUser.class)) {
                throw new OctopusUnauthorizedException("User required", infoProducer.getViolationInfo(accessContext));
            }

            // TODO Verify how this can be configured. They are the shiro ones.
            RequiresRoles roles = getAnnotation(annotations, RequiresRoles.class);

            if (roles != null) {
                subject.checkRoles(Arrays.asList(roles.value()));
            }

            RequiresPermissions permissions = getAnnotation(annotations, RequiresPermissions.class);

            if (permissions != null) {
                subject.checkPermissions(permissions.value());
            }

            if (config.getNamedPermissionCheckClass() != null) {

                Annotation namedPermissionCheck = getAnnotation(annotations, config.getNamedPermissionCheckClass());
                if (namedPermissionCheck != null) {
                    Set<SecurityViolation> securityViolations = performNamedPermissionChecks(namedPermissionCheck, accessContext);
                    if (!securityViolations.isEmpty()) {

                        throw new OctopusUnauthorizedException(securityViolations);
                    }
                }
            }

            if (config.getNamedRoleCheckClass() != null) {

                Annotation namedRoleCheck = getAnnotation(annotations, config.getNamedRoleCheckClass());
                if (namedRoleCheck != null) {
                    Set<SecurityViolation> securityViolations = performNamedRoleChecks(namedRoleCheck, accessContext);
                    if (!securityViolations.isEmpty()) {

                        throw new OctopusUnauthorizedException(securityViolations);
                    }
                }
            }

            CustomVoterCheck customCheck = getAnnotation(annotations, CustomVoterCheck.class);

            if (customCheck != null) {
                Set<SecurityViolation> securityViolations = performCustomChecks(customCheck, accessContext);
                if (!securityViolations.isEmpty()) {

                    throw new OctopusUnauthorizedException(securityViolations);
                }
            }

        }

        return context.proceed();
    }

    private Set<SecurityViolation> performNamedPermissionChecks(Annotation customNamedCheck, AccessDecisionVoterContext context) {
        Set<SecurityViolation> result = new HashSet<SecurityViolation>();

        BeanManager beanmanager = BeanManagerProvider.getInstance().getBeanManager();

        for (Object permissionConstant : AnnotationUtil.getPermissionValues(customNamedCheck)) {
            String beanName = nameFactory.generatePermissionBeanName(((NamedPermission) permissionConstant).name());

            GenericPermissionVoter voter = CDIUtil.getContextualReferenceByName(beanmanager, beanName
                    , GenericPermissionVoter.class);
            result.addAll(voter.checkPermission(context));

        }
        return result;
    }

    private Set<SecurityViolation> performNamedRoleChecks(Annotation customNamedCheck, AccessDecisionVoterContext context) {
        Set<SecurityViolation> result = new HashSet<SecurityViolation>();

        BeanManager beanmanager = BeanManagerProvider.getInstance().getBeanManager();

        for (Object permissionConstant : AnnotationUtil.getRoleValues(customNamedCheck)) {
            String beanName = nameFactory.generateRoleBeanName(((NamedRole) permissionConstant).name());

            GenericPermissionVoter voter = CDIUtil.getContextualReferenceByName(beanmanager, beanName
                    , GenericPermissionVoter.class);
            result.addAll(voter.checkPermission(context));

        }
        return result;
    }

    private Set<SecurityViolation> performCustomChecks(CustomVoterCheck customCheck, AccessDecisionVoterContext context) {
        Set<SecurityViolation> result = new HashSet<SecurityViolation>();
        for (Class<? extends AbstractAccessDecisionVoter> clsName : customCheck.value()) {
            AbstractAccessDecisionVoter voter = BeanProvider.getContextualReference(clsName);
            result.addAll(voter.checkPermission(context));
        }

        return result;
    }

    private Set<?> getAllAnnotations(Class<?> someClassType, Method someMethod) {

        Set<Object> result = new HashSet<Object>();
        result.add(someMethod.getAnnotation(PermitAll.class));
        result.add(someMethod.getAnnotation(RequiresAuthentication.class));
        result.add(someMethod.getAnnotation(RequiresGuest.class));
        result.add(someMethod.getAnnotation(RequiresUser.class));
        result.add(someMethod.getAnnotation(RequiresRoles.class));
        result.add(someMethod.getAnnotation(RequiresPermissions.class));
        result.add(someMethod.getAnnotation(CustomVoterCheck.class));
        result.add(someMethod.getAnnotation(OnlyDuringAuthentication.class));
        if (config.getNamedPermissionCheckClass() != null) {
            result.add(someMethod.getAnnotation(config.getNamedPermissionCheckClass()));
        }
        if (config.getNamedRoleCheckClass() != null) {
            result.add(someMethod.getAnnotation(config.getNamedRoleCheckClass()));
        }
        result.add(getAnnotation(someClassType, PermitAll.class));
        result.add(getAnnotation(someClassType, RequiresAuthentication.class));
        result.add(getAnnotation(someClassType, RequiresGuest.class));
        result.add(getAnnotation(someClassType, RequiresUser.class));
        result.add(getAnnotation(someClassType, RequiresRoles.class));
        result.add(getAnnotation(someClassType, RequiresPermissions.class));
        if (config.getNamedPermissionCheckClass() != null) {
            result.add(getAnnotation(someClassType, config.getNamedPermissionCheckClass()));
        }
        if (config.getNamedRoleCheckClass() != null) {
            result.add(getAnnotation(someClassType, config.getNamedRoleCheckClass()));
        }
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
            if (someAnnotation.isAssignableFrom(item.getClass())) {
                result = item;
            }
        }
        return (A) result;
    }
}
