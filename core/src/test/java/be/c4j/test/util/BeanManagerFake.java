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
package be.c4j.test.util;

import org.apache.deltaspike.core.api.literal.AnyLiteral;
import org.apache.deltaspike.core.api.provider.BeanManagerProvider;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.util.*;

import static org.mockito.Matchers.anySet;
import static org.mockito.Mockito.*;

/**
 *
 */
public class BeanManagerFake {

    private BeanManager beanManagerMock;

    private Map<Class<?>, List<InstanceAndQualifier>> registeredObjects;
    private Map<String, Object> registeredBeans;

    public BeanManagerFake() {
        beanManagerMock = mock(BeanManager.class);

        BeanManagerProvider provider = new BeanManagerProvider();

        provider.setBeanManager(null, beanManagerMock);

        registeredObjects = new HashMap<Class<?>, List<InstanceAndQualifier>>();
        registeredBeans = new HashMap<String, Object>();
    }

    public void registerBean(Object instance, Class<?> typeToRegister) {
        registerBean(instance, typeToRegister, new AnyLiteral());
    }

    public void registerBean(Object instance, Class<?> typeToRegister, Annotation qualifier) {
        List<InstanceAndQualifier> objects = registeredObjects.get(typeToRegister);
        if (objects == null) {
            objects = new ArrayList<InstanceAndQualifier>();
            registeredObjects.put(typeToRegister, objects);
        }
        objects.add(new InstanceAndQualifier(instance, qualifier));
    }

    public void registerBean(String beanName, Object instance) {
        registeredBeans.put(beanName, instance);
    }

    public void endRegistration() {
        for (Map.Entry<Class<?>, List<InstanceAndQualifier>> entry : registeredObjects.entrySet()) {
            Map<Annotation, Set<Bean<?>>> beans = new HashMap<Annotation, Set<Bean<?>>>();
            for (InstanceAndQualifier obj : entry.getValue()) {
                Set<Bean<?>> set = beans.get(obj.getQualifier());
                if (set == null) {
                    set = new HashSet<Bean<?>>();
                    beans.put(obj.getQualifier(), set);
                }

                set.add(new FakeBean<Object>(obj.getInstance()));
            }

            for (Map.Entry<Annotation, Set<Bean<?>>> beanEntry : beans.entrySet()) {

                when(beanManagerMock.getBeans(entry.getKey(), beanEntry.getKey())).thenReturn(beanEntry.getValue());
                when(beanManagerMock.getBeans(entry.getKey())).thenReturn(beanEntry.getValue());

                for (Bean<?> bean : beanEntry.getValue()) {

                    when(beanManagerMock.getReference(bean, entry.getKey(), null)).thenReturn(((FakeBean) bean).getRealBean());
                }
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

    private static class InstanceAndQualifier {
        private Object instance;
        private Annotation qualifier;

        public InstanceAndQualifier(Object instance, Annotation qualifier) {
            this.instance = instance;
            this.qualifier = qualifier;
        }

        public Object getInstance() {
            return instance;
        }

        public Annotation getQualifier() {
            return qualifier;
        }
    }
}
