/*
 * Copyright 2014-2016 Rudy De Busscher
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
package be.c4j.test.util;

import org.apache.deltaspike.core.api.literal.AnyLiteral;
import org.apache.deltaspike.core.api.provider.BeanManagerProvider;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import java.lang.reflect.Field;
import java.util.*;

import static org.mockito.Matchers.anySet;
import static org.mockito.Mockito.*;

/**
 *
 */
public class BeanManagerFake {

    private BeanManager beanManagerMock;

    private Map<Class<?>, List<Object>> registeredObjects;
    private Map<String, Object> registeredBeans;

    public BeanManagerFake() {
        beanManagerMock = mock(BeanManager.class);

        BeanManagerProvider provider = new BeanManagerProvider();

        provider.setBeanManager(null, beanManagerMock);

        registeredObjects = new HashMap<Class<?>, List<Object>>();
        registeredBeans = new HashMap<String, Object>();
    }

    public void registerBean(Object instance, Class<?> typeToRegister) {
        List<Object> objects = registeredObjects.get(typeToRegister);
        if (objects == null) {
            objects = new ArrayList<Object>();
            registeredObjects.put(typeToRegister, objects);
        }
        objects.add(instance);
    }

    public void registerBean(String beanName, Object instance) {
        registeredBeans.put(beanName, instance);
    }

    public void endRegistration() {
        for (Map.Entry<Class<?>, List<Object>> entry : registeredObjects.entrySet()) {
            Set<Bean<?>> beans = new HashSet<Bean<?>>();
            for (Object obj : entry.getValue()) {
                beans.add(new FakeBean<Object>(obj));
            }
            when(beanManagerMock.getBeans(entry.getKey(), new AnyLiteral())).thenReturn(beans);
            when(beanManagerMock.getBeans(entry.getKey())).thenReturn(beans);

            for (Bean<?> bean : beans) {

                when(beanManagerMock.getReference(bean, entry.getKey(), null)).thenReturn(((FakeBean) bean).getRealBean());
            }
        }

        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                Set arg = (Set) invocationOnMock.getArguments()[0];
                return arg.iterator().next();
            }
        }).when(beanManagerMock).resolve(anySet());

        for (Map.Entry<String, Object> entry : registeredBeans.entrySet()) {
            Set<Bean<?>> beans = new HashSet<Bean<?>>();
            Bean<?> bean = new FakeBean<Object>(entry.getValue());
            beans.add(bean);

            when(beanManagerMock.getBeans(entry.getKey())).thenReturn(beans);
            when(beanManagerMock.getReference(bean, Object.class, null)).thenReturn(entry.getValue());
        }

    }

    public void deregistration() {

        try {
            Field field = BeanManagerProvider.class.getDeclaredField("bmpSingleton");
            field.setAccessible(true);
            field.set(null, null); // set null to the static field (instance == null)
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }

        reset(beanManagerMock);
        beanManagerMock = null;
    }
}
