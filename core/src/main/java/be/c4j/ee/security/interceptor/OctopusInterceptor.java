/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.interceptor;

import be.c4j.ee.security.CustomAccessDecissionVoterContext;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.context.OctopusSecurityContext;
import be.c4j.ee.security.custom.CustomVoterCheck;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.interceptor.checks.AnnotationCheckFactory;
import be.c4j.ee.security.interceptor.checks.SecurityCheckInfo;
import be.c4j.ee.security.realm.OnlyDuringAuthentication;
import be.c4j.ee.security.realm.OnlyDuringAuthenticationEvent;
import be.c4j.ee.security.realm.OnlyDuringAuthorization;
import be.c4j.ee.security.systemaccount.SystemAccount;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.*;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;

import javax.annotation.security.PermitAll;
import javax.ejb.Asynchronous;
import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;
import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Iterator;
import java.util.Set;

@Interceptor
@OctopusInterceptorBinding
public class OctopusInterceptor implements Serializable {

    private static final long serialVersionUID = 1L;

    @Inject
    private OctopusConfig config;

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    @Inject
    private AnnotationCheckFactory annotationCheckFactory;

    //@PostConstruct With Weld 2.X, there seems to be an issue
    public void init(InvocationContext context) {
        if (config == null) {
            // WLS12C doesn't inject into interceptors
            config = BeanProvider.getContextualReference(OctopusConfig.class);
            infoProducer = BeanProvider.getContextualReference(SecurityViolationInfoProducer.class);
            annotationCheckFactory = BeanProvider.getContextualReference(AnnotationCheckFactory.class);
        }
    }

    @AroundInvoke
    public Object interceptShiroSecurity(InvocationContext context) throws Exception {
        init(context);  // Since @PostConstruct isn't allowed in Weld 2.x

        Class<?> classType = context.getTarget().getClass();
        Method method = context.getMethod();

        supportForAsynchronousEJB(context, method);

        AccessDecisionVoterContext accessContext = new CustomAccessDecissionVoterContext(context);

        AnnotationInfo info = getAllAnnotations(classType, method);

        boolean accessAllowed = false;
        OctopusUnauthorizedException exception = null;
        // We need to check at 2 levels, method and then if not present at class level
        Set<Annotation> annotations = info.getMethodAnnotations();
        if (!annotations.isEmpty()) {
            if (hasAnnotation(annotations, PermitAll.class)) {
                accessAllowed = true;
            } else {
                Subject subject = SecurityUtils.getSubject();
                Iterator<Annotation> annotationIterator = annotations.iterator();

                while (!accessAllowed && annotationIterator.hasNext()) {
                    Annotation annotation = annotationIterator.next();
                    SecurityCheckInfo checkInfo = annotationCheckFactory.getCheck(annotation).performCheck(subject, accessContext, annotation);
                    if (checkInfo.isAccessAllowed()) {
                        accessAllowed = true;
                    }
                    if (checkInfo.getException() != null) {
                        exception = checkInfo.getException();
                    }

                }
            }
            if (!accessAllowed && exception != null) {
                throw exception;
            }
        }

        if (!accessAllowed) {
            // OK, at method level we didn't find any annotations.
            annotations = info.getClassAnnotations();

            if (!annotations.isEmpty()) {
                if (hasAnnotation(annotations, PermitAll.class)) {
                    accessAllowed = true;
                } else {
                    Subject subject = SecurityUtils.getSubject();

                    Iterator<Annotation> annotationIterator = annotations.iterator();

                    while (!accessAllowed && annotationIterator.hasNext()) {
                        Annotation annotation = annotationIterator.next();
                        SecurityCheckInfo checkInfo = annotationCheckFactory.getCheck(annotation).performCheck(subject, accessContext, annotation);
                        if (checkInfo.isAccessAllowed()) {
                            accessAllowed = true;
                        }
                        if (checkInfo.getException() != null) {
                            exception = checkInfo.getException();
                        }

                    }
                }
                if (!accessAllowed && exception != null) {
                    throw exception;
                }
            }

        }
        if (!accessAllowed) {
            // Ok at classLevel also no info -> Exception
            throw new OctopusUnauthorizedException("No Authorization requirements available", infoProducer.getViolationInfo(accessContext));
        }
        return context.proceed();
    }

    private void supportForAsynchronousEJB(InvocationContext context, Method method) {
        Asynchronous asynchronous = method.getAnnotation(Asynchronous.class);
        if (asynchronous != null) {
            for (Object parameter : context.getParameters()) {

                if (parameter != null && OctopusSecurityContext.class.isAssignableFrom(parameter.getClass())) {
                    Subject subject = ((OctopusSecurityContext) parameter).getSubject();
                    ThreadContext.bind(subject);
                }
            }
        }
    }

    private AnnotationInfo getAllAnnotations(Class<?> someClassType, Method someMethod) {
        AnnotationInfo result = new AnnotationInfo();

        result.addMethodAnnotation(someMethod.getAnnotation(PermitAll.class));
        result.addMethodAnnotation(someMethod.getAnnotation(RequiresAuthentication.class));
        result.addMethodAnnotation(someMethod.getAnnotation(RequiresGuest.class));
        result.addMethodAnnotation(someMethod.getAnnotation(RequiresUser.class));
        result.addMethodAnnotation(someMethod.getAnnotation(RequiresRoles.class));
        result.addMethodAnnotation(someMethod.getAnnotation(RequiresPermissions.class));
        result.addMethodAnnotation(someMethod.getAnnotation(CustomVoterCheck.class));
        result.addMethodAnnotation(someMethod.getAnnotation(SystemAccount.class));
        result.addMethodAnnotation(someMethod.getAnnotation(OnlyDuringAuthorization.class));
        result.addMethodAnnotation(someMethod.getAnnotation(OnlyDuringAuthentication.class));
        result.addMethodAnnotation(someMethod.getAnnotation(OnlyDuringAuthenticationEvent.class));
        if (config.getNamedPermissionCheckClass() != null) {
            result.addMethodAnnotation(someMethod.getAnnotation(config.getNamedPermissionCheckClass()));
        }
        if (config.getNamedRoleCheckClass() != null) {
            result.addMethodAnnotation(someMethod.getAnnotation(config.getNamedRoleCheckClass()));
        }
        result.addClassAnnotation(getAnnotation(someClassType, PermitAll.class));
        result.addClassAnnotation(getAnnotation(someClassType, RequiresAuthentication.class));
        result.addClassAnnotation(getAnnotation(someClassType, RequiresGuest.class));
        result.addClassAnnotation(getAnnotation(someClassType, RequiresUser.class));
        result.addClassAnnotation(getAnnotation(someClassType, RequiresRoles.class));
        result.addClassAnnotation(getAnnotation(someClassType, RequiresPermissions.class));
        result.addClassAnnotation(getAnnotation(someClassType, CustomVoterCheck.class));
        result.addClassAnnotation(getAnnotation(someClassType, SystemAccount.class));
        if (config.getNamedPermissionCheckClass() != null) {
            result.addClassAnnotation(getAnnotation(someClassType, config.getNamedPermissionCheckClass()));
        }
        if (config.getNamedRoleCheckClass() != null) {
            result.addClassAnnotation(getAnnotation(someClassType, config.getNamedRoleCheckClass()));
        }

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
