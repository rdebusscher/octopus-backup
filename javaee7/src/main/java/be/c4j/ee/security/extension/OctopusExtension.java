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
package be.c4j.ee.security.extension;


import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.util.CDIUtil;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.*;

public class OctopusExtension extends OctopusBaseExtension {

    private Class<OctopusConfig> configClass = OctopusConfig.class;
    private Class<VoterNameFactory> voterNameFactoryClass = VoterNameFactory.class;

    void keepProducerMethods(@Observes ProcessProducerMethod producerMethod) {
        CDIUtil.registerOptionalBean(producerMethod.getAnnotatedProducerMethod().getJavaMember());
    }

    <T> void collectImplementations(@Observes ProcessAnnotatedType<T> pat, BeanManager beanManager) {
        AnnotatedType<T> annotatedType = pat.getAnnotatedType();
        if (OctopusConfig.class.equals(annotatedType.getJavaClass().getSuperclass())) {
            configClass = (Class<OctopusConfig>) annotatedType.getJavaClass();
        }

        if (VoterNameFactory.class.equals(annotatedType.getJavaClass().getSuperclass())) {
            voterNameFactoryClass = (Class<VoterNameFactory>) annotatedType.getJavaClass();
        }

    }

    void configModule(@Observes AfterBeanDiscovery afterBeanDiscovery, BeanManager beanManager) {
        config = getUnmanagedInstance(beanManager, configClass);

        nameFactory = getUnmanagedInstance(beanManager, voterNameFactoryClass);

        createPermissionVoters(afterBeanDiscovery, beanManager);
        createRoleVoters(afterBeanDiscovery, beanManager);

    }

    private <T> T getUnmanagedInstance(BeanManager beanManager, Class<T> beanClass) {
        Unmanaged<T> unmanagedConfig = new Unmanaged<T>(beanManager, beanClass);
        Unmanaged.UnmanagedInstance<? extends T> configInstance = unmanagedConfig.newInstance();
        return configInstance.produce().inject().postConstruct().get();
    }

}
