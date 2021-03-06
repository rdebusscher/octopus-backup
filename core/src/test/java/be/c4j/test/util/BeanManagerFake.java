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
import org.apache.deltaspike.core.util.metadata.builder.AnnotatedTypeBuilder;
import org.junit.Assert;
import org.mockito.ArgumentMatchers;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.spi.*;
import javax.inject.Inject;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.util.*;

import static org.junit.Assert.fail;
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

        handleCreateAnnotatedTypeMethod();

        when(beanManagerMock.createInjectionTarget(any(AnnotatedType.class))).thenAnswer(new Answer<InjectionTarget>() {
            @Override
            public InjectionTarget answer(InvocationOnMock invocation) throws Throwable {
                return new FakeInjectionTarget((AnnotatedType) invocation.getArgument(0));
            }
        });
    }

    private void handleCreateAnnotatedTypeMethod() {
        when(beanManagerMock.createAnnotatedType(any(Class.class))).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                AnnotatedTypeBuilder typeBuilder = new AnnotatedTypeBuilder();
                typeBuilder.readFromType((Class) invocation.getArgument(0));
                return typeBuilder.create();
            }
        });
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

        Set<Bean<?>> beanSet = ArgumentMatchers.anySet();
        when(beanManagerMock.resolve(beanSet)).thenAnswer(new Answer<Bean<?>>() {
            @Override
            public Bean<?> answer(InvocationOnMock invocation) throws Throwable {
                Set<Bean<?>> arg = (Set<Bean<?>>) invocation.getArguments()[0];
                return arg.iterator().next();
            }
        });

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
            Assert.fail(e.getMessage());
            //Should never happen
        } catch (IllegalAccessException e) {
            Assert.fail(e.getMessage());
            //Should never happen
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


    private class FakeInjectionTarget<T> implements InjectionTarget<T> {


        private AnnotatedType<T> annotatedType;

        public FakeInjectionTarget(AnnotatedType<T> annotatedType) {
            this.annotatedType = annotatedType;
        }

        @Override
        public void inject(T instance, CreationalContext<T> ctx) {
            for (AnnotatedField<? super T> annotatedField : annotatedType.getFields()) {
                if (annotatedField.isAnnotationPresent(Inject.class)) {
                    List<InstanceAndQualifier> instanceAndQualifiers = registeredObjects.get(annotatedField.getBaseType());
                    if (instanceAndQualifiers == null) {
                        fail("No candidates for injection into field " + annotatedField.getJavaMember().getName());
                    }
                    if (instanceAndQualifiers.size() != 1) {
                        // Maybe it would be nice to have to also check on the qualifiers :)
                        fail("Multiple candidates for injection into field " + annotatedField.getJavaMember().getName());
                    }
                    try {
                        ReflectionUtil.setFieldValue(instance, annotatedField.getJavaMember().getName()
                                , instanceAndQualifiers.get(0).getInstance());
                    } catch (NoSuchFieldException e) {
                        fail(e.getMessage());
                    } catch (IllegalAccessException e) {
                        fail(e.getMessage());
                    }
                }
            }
        }

        @Override
        public void postConstruct(T instance) {

        }

        @Override
        public void preDestroy(T instance) {

        }

        @Override
        public T produce(CreationalContext<T> creationalContext) {
            return null;
        }

        @Override
        public void dispose(T instance) {

        }

        @Override
        public Set<InjectionPoint> getInjectionPoints() {
            return null;
        }
    }
}
