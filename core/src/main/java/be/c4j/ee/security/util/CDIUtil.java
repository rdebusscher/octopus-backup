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
package be.c4j.ee.security.util;

import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public final class CDIUtil {

    private static final Map<Class<?>, Method> OPTIONAL_BEAN_INFO = new HashMap<Class<?>, Method>();
    private static final Map<Class<?>, Object> OPTIONAL_BEAN = new HashMap<Class<?>, Object>();

    private CDIUtil() {
    }

    public static <T> T getBeanManually(Class<T> targetClass) {
        T result = null;

        if (OPTIONAL_BEAN.containsKey(targetClass)) {
            result = (T) OPTIONAL_BEAN.get(targetClass);
        } else {
            if (OPTIONAL_BEAN_INFO.containsKey(targetClass)) {
                Method method = OPTIONAL_BEAN_INFO.get(targetClass);
                Object bean = CodiUtils.getContextualReferenceByClass(method.getDeclaringClass());
                try {
                    result = (T) method.invoke(bean);
                    OPTIONAL_BEAN.put(targetClass, result);
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                } catch (InvocationTargetException e) {
                    e.printStackTrace();
                }
            }
        }
        return result;

    }

    public static <T> T getOptionalBean(Class<T> targetClass) {
        T result;
        try {
            result = CodiUtils.getContextualReferenceByClass(targetClass);
        } catch (IllegalStateException e) {
            // OpenWebBeans is stricter (as per spec should) and beans with generic types doesn't match in our case.
            // But we also use it for optional beans
            result = CDIUtil.getBeanManually(targetClass);
        }
        return result;
    }

    public static void registerOptionalBean(Method producerMethod) {
        OPTIONAL_BEAN_INFO.put(producerMethod.getReturnType(), producerMethod);
    }
}
