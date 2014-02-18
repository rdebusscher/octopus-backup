/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package be.c4j.ee.security.extension;


import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.config.SecurityModuleConfig;
import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.beans.BeanBuilder;
import be.c4j.ee.security.beans.metadata.DelegatingContextualLifecycle;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.permission.PermissionLookup;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;
import org.apache.myfaces.extensions.cdi.core.impl.util.NamedLiteral;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.*;

public class PermissionVoterExtension implements Extension {

    void createPermissionVoters(final @Observes AfterBeanDiscovery afterBeanDiscovery, final BeanManager beanManager) {
        VoterNameFactory nameFactory = CodiUtils.getContextualReferenceByClass(beanManager, VoterNameFactory.class);
        SecurityModuleConfig config = CodiUtils.getContextualReferenceByClass(beanManager, SecurityModuleConfig.class);

        Class<? extends NamedPermission> c = config.getNamedPermissionClass();

        Object[] constants = c.getEnumConstants();

        AnnotatedType<GenericPermissionVoter> permissionVoterAnnotatedType = beanManager
                .createAnnotatedType(GenericPermissionVoter.class);
        InjectionTarget<GenericPermissionVoter> voterInjectionTarget = beanManager
                .createInjectionTarget(permissionVoterAnnotatedType);

        NamedPermission namedPermission;
        String beanName;

        for (Object permission : constants) {
            namedPermission = (NamedPermission) permission;
            beanName = nameFactory.generatePermissionBeanName(namedPermission.name());

            Bean<GenericPermissionVoter> bean = new BeanBuilder<GenericPermissionVoter>(beanManager)
                    .passivationCapable(false).beanClass(GenericPermissionVoter.class)
                    .injectionPoints(voterInjectionTarget.getInjectionPoints()).name(beanName)
                    .scope(ApplicationScoped.class).addQualifier(new NamedLiteral(beanName))
                    .beanLifecycle(new LifecycleCallback(voterInjectionTarget, namedPermission)).create();
            afterBeanDiscovery.addBean(bean);
        }
    }



    private static class LifecycleCallback extends DelegatingContextualLifecycle<GenericPermissionVoter> {

        private NamedPermission namedPermission;

        public LifecycleCallback(InjectionTarget<GenericPermissionVoter> injectionTarget, NamedPermission
                someNamedPermission) {
            super(injectionTarget);
            namedPermission = someNamedPermission;
        }

        @Override
        public GenericPermissionVoter create(Bean<GenericPermissionVoter> bean,
                                             CreationalContext<GenericPermissionVoter> creationalContext) {
            GenericPermissionVoter result = super.create(bean, creationalContext);

            // We can't move this to the Extension itself.
            // The producer of this PermissionLookup goes to the database and this isn't possible until we are completely ready.

            PermissionLookup<? extends NamedPermission> permissionLookup = CodiUtils.getContextualReferenceByClass(PermissionLookup.class);


            result.setNamedPermission(permissionLookup.getPermission(namedPermission.name()));
            return result;
        }

        @Override
        public void destroy(Bean<GenericPermissionVoter> bean, GenericPermissionVoter instance,
                            CreationalContext<GenericPermissionVoter> creationalContext) {
            super.destroy(bean, instance, creationalContext);
        }
    }
}
