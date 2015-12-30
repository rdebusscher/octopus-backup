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


import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ejb.EJBException;
import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
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

    private static final Logger LOGGER = LoggerFactory.getLogger(CDIUtil.class);

    private CDIUtil() {
    }

    /**
     * Return the instance of bean for that class defined by Producers. But we can't use an @Inject because the execution comes to early.
     *
     * @param targetClass
     * @param <T>
     * @return the bean instance
     */
    public static <T> T getBeanManually(Class<T> targetClass, boolean optional) {
        T result = null;

        if (OPTIONAL_BEAN.containsKey(targetClass)) {
            result = (T) OPTIONAL_BEAN.get(targetClass);
        } else {
            if (OPTIONAL_BEAN_INFO.containsKey(targetClass)) {
                Method method = OPTIONAL_BEAN_INFO.get(targetClass);
                Object bean = BeanProvider.getContextualReference(method.getDeclaringClass());
                try {
                    result = (T) method.invoke(bean);
                    OPTIONAL_BEAN.put(targetClass, result);
                } catch (IllegalAccessException e) {
                    LOGGER.error("Exception occured during invocation of producer method", e);
                } catch (InvocationTargetException e) {
                    if (e.getTargetException() instanceof EJBException) {
                        EJBException ejbException = (EJBException) e.getTargetException();
                        if (ejbException.getCause() instanceof OctopusUnauthorizedException) {
                            OctopusUnauthorizedException exception = (OctopusUnauthorizedException) ejbException.getCause();
                            throw exception;
                        }
                    }
                }
            }
        }
        if (result == null && !optional) {
            throw new IllegalArgumentException("No bean found for " + targetClass.getName());
        }
        return result;

    }

    public static <T> T getOptionalBean(Class<T> targetClass) {
        T result;
        try {
            result = BeanProvider.getContextualReference(targetClass);
        } catch (IllegalStateException e) {
            // OpenWebBeans is stricter (as per spec should) and beans with generic types doesn't match in our case.
            // But we also use it for optional beans
            result = CDIUtil.getBeanManually(targetClass, true);
        }
        return result;
    }

    public static void registerOptionalBean(Method producerMethod) {
        OPTIONAL_BEAN_INFO.put(producerMethod.getReturnType(), producerMethod);
    }

    public static <T> T getContextualReferenceByName(BeanManager beanManager, String beanName, Class<T> targetClass) {
        T result = null;
        // CodiUtils.getContextualReferenceByName() isn't working on WLS in some cases as WLS only stores the type of the actual class and not all superclasses
        Bean bean = beanManager.getBeans(beanName).iterator().next();
        CreationalContext ctx = beanManager.createCreationalContext(bean);
        Object o = beanManager.getReference(bean, Object.class, ctx);
        if (targetClass.isAssignableFrom(o.getClass())) {
            result = (T) o;
        }
        return result;
    }
}
