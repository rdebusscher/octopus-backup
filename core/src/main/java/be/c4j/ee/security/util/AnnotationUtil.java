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
package be.c4j.ee.security.util;

import be.c4j.ee.security.Combined;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.custom.CustomVoterCheck;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.interceptor.AnnotationInfo;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.realm.*;
import be.c4j.ee.security.role.NamedRole;
import be.c4j.ee.security.systemaccount.SystemAccount;
import org.apache.deltaspike.core.api.provider.BeanManagerProvider;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.authz.annotation.*;

import javax.annotation.security.PermitAll;
import javax.enterprise.inject.spi.BeanManager;
import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public final class AnnotationUtil {

    private AnnotationUtil() {
    }

    public static <T extends NamedPermission> T[] getPermissionValues(Annotation someCustomNamedCheck) {
        T[] result = null;
        for (Method method : someCustomNamedCheck.getClass().getDeclaredMethods()) {
            if ("value".equals(method.getName())) {
                try {
                    result = (T[]) method.invoke(someCustomNamedCheck, null);
                } catch (IllegalAccessException e) {
                    throw new OctopusUnexpectedException(e);
                } catch (InvocationTargetException e) {
                    throw new OctopusUnexpectedException(e);
                }
            }
        }

        return result;
    }

    public static String[] getStringValues(Annotation someCustomNamedCheck) {
        String[] result = null;
        for (Method method : someCustomNamedCheck.getClass().getDeclaredMethods()) {
            if ("value".equals(method.getName())) {
                try {
                    result = (String[]) method.invoke(someCustomNamedCheck, null);

                } catch (IllegalAccessException e) {
                    throw new OctopusUnexpectedException(e);
                } catch (InvocationTargetException e) {
                    throw new OctopusUnexpectedException(e);
                }
            }
        }

        return result;
    }

    public static <T extends NamedRole> T[] getRoleValues(Annotation someCustomRoleCheck) {
        T[] result = null;
        for (Method method : someCustomRoleCheck.getClass().getDeclaredMethods()) {
            if ("value".equals(method.getName())) {
                try {
                    result = (T[]) method.invoke(someCustomRoleCheck, null);

                } catch (IllegalAccessException e) {
                    throw new OctopusUnexpectedException(e);
                } catch (InvocationTargetException e) {
                    throw new OctopusUnexpectedException(e);
                }
            }
        }

        return result;
    }

    public static Combined getPermissionCombination(Annotation customAnnotation) {
        String value = null;
        for (Method method : customAnnotation.getClass().getDeclaredMethods()) {
            if ("combine".equals(method.getName())) {
                try {
                    value = method.invoke(customAnnotation, null).toString();

                } catch (IllegalAccessException e) {
                    throw new OctopusUnexpectedException(e);
                } catch (InvocationTargetException e) {
                    throw new OctopusUnexpectedException(e);
                }
            }
        }
        return Combined.findFor(value);
    }

    /* Retrieve the supported annotation enforcing authorization for the method */
    public static AnnotationInfo getAllAnnotations(OctopusConfig config, Class<?> someClassType, Method someMethod) {

        List<AnnotationsToFind> annotationsToFindList = BeanProvider.getContextualReferences(AnnotationsToFind.class, true);
        AnnotationInfo result = new AnnotationInfo();

        result.addMethodAnnotation(someMethod.getAnnotation(PermitAll.class));
        result.addMethodAnnotation(someMethod.getAnnotation(RequiresAuthentication.class));
        result.addMethodAnnotation(someMethod.getAnnotation(RequiresGuest.class));
        result.addMethodAnnotation(someMethod.getAnnotation(RequiresUser.class));
        result.addMethodAnnotation(someMethod.getAnnotation(RequiresRoles.class));
        result.addMethodAnnotation(someMethod.getAnnotation(RequiresPermissions.class));
        result.addMethodAnnotation(someMethod.getAnnotation(OctopusPermissions.class));
        result.addMethodAnnotation(someMethod.getAnnotation(OctopusRoles.class));
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
        for (AnnotationsToFind annotationsToFind : annotationsToFindList) {
            for (Class<? extends Annotation> annotationClass : annotationsToFind.getList()) {
                result.addMethodAnnotation(someMethod.getAnnotation(annotationClass));
            }
        }
        result.addClassAnnotation(getAnnotation(someClassType, PermitAll.class));
        result.addClassAnnotation(getAnnotation(someClassType, RequiresAuthentication.class));
        result.addClassAnnotation(getAnnotation(someClassType, RequiresGuest.class));
        result.addClassAnnotation(getAnnotation(someClassType, RequiresUser.class));
        result.addClassAnnotation(getAnnotation(someClassType, RequiresRoles.class));
        result.addClassAnnotation(getAnnotation(someClassType, RequiresPermissions.class));
        result.addClassAnnotation(getAnnotation(someClassType, OctopusPermissions.class));
        result.addClassAnnotation(getAnnotation(someClassType, OctopusRoles.class));
        result.addClassAnnotation(getAnnotation(someClassType, CustomVoterCheck.class));
        result.addClassAnnotation(getAnnotation(someClassType, SystemAccount.class));
        if (config.getNamedPermissionCheckClass() != null) {
            result.addClassAnnotation(getAnnotation(someClassType, config.getNamedPermissionCheckClass()));
        }
        if (config.getNamedRoleCheckClass() != null) {
            result.addClassAnnotation(getAnnotation(someClassType, config.getNamedRoleCheckClass()));
        }
        for (AnnotationsToFind annotationsToFind : annotationsToFindList) {
            for (Class<? extends Annotation> annotationClass : annotationsToFind.getList()) {
                result.addClassAnnotation(getAnnotation(someClassType, annotationClass));
            }
        }


        return result;
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

    public static <A extends Annotation> boolean hasAnnotation(Set<?> annotations, Class<A> someAnnotation) {
        return getAnnotation(annotations, someAnnotation) != null;
    }

    // TODO Review Was private and now made public but I guess it can be used elsewhere.
    public static <A extends Annotation> A getAnnotation(Set<?> annotations, Class<A> someAnnotation) {
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
