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
package be.c4j.util;

import java.lang.reflect.Field;

/**
 *
 */
public final class ReflectionUtil {

    private ReflectionUtil() {
    }

    /**
     * Injects objects into the target (private) fields by matching the type.
     *
     * @param target       The target object where the dependencies are injected
     * @param dependencies The objects we like to set into the target.
     * @throws IllegalAccessException Should not happen since we overrule the accessibility
     */
    public static void injectDependencies(final Object target, final Object... dependencies) throws IllegalAccessException {
        Class targetClass = target.getClass();
        while (targetClass != null && targetClass != Object.class) {
            if (targetClass.getName().contains("$")) {
                targetClass = targetClass.getSuperclass();
            }
            for (Field field : targetClass.getDeclaredFields()) {
                field.setAccessible(true);
                for (Object dependency : dependencies) {
                    if (field.getType().isAssignableFrom(dependency.getClass())) {
                        field.set(target, dependency);
                    }
                }

            }
            targetClass = targetClass.getSuperclass();
        }
    }
}
