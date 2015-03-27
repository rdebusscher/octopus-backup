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
package be.c4j.ee.security.util;

import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.role.NamedRole;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

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
                    e.printStackTrace();
                } catch (InvocationTargetException e) {
                    e.printStackTrace();
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
                    e.printStackTrace();
                } catch (InvocationTargetException e) {
                    e.printStackTrace();
                }
            }
        }

        return result;
    }
}
