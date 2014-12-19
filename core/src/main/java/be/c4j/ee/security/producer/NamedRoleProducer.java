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
package be.c4j.ee.security.producer;

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.config.VoterNameFactory;
import be.c4j.ee.security.role.GenericRoleVoter;
import be.c4j.ee.security.role.NamedApplicationRole;
import be.c4j.ee.security.role.NamedRole;
import be.c4j.ee.security.role.RoleLookup;
import be.c4j.ee.security.util.AnnotationUtil;
import be.c4j.ee.security.util.CDIUtil;
import org.apache.deltaspike.core.api.provider.BeanManagerProvider;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.AmbiguousResolutionException;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.UnsatisfiedResolutionException;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.inject.Inject;
import java.lang.annotation.Annotation;

@ApplicationScoped
public class NamedRoleProducer {

    @Inject
    private OctopusConfig config;

    @Inject
    private VoterNameFactory nameFactory;

    private RoleLookup<? extends NamedRole> lookup;

    @Inject
    private BeanManager beanManager;

    @PostConstruct
    public void init() {
        lookup = CDIUtil.getBeanManually(RoleLookup.class);
    }

    @Produces
    public GenericRoleVoter getVoter(InjectionPoint injectionPoint) {
        Annotation annotation = injectionPoint.getAnnotated().getAnnotation(config.getNamedRoleCheckClass());
        if (annotation == null) {
            throw new UnsatisfiedResolutionException(
                    "Injection points for GenericRoleVoter needs an additional " + config.getNamedRoleCheck() +
                            " annotation to determine the correct bean");
        }
        NamedRole[] roles = AnnotationUtil.getRoleValues(annotation);
        if (roles.length>1) {
            throw new AmbiguousResolutionException("Only one named role can be specified.");
        }


        return CDIUtil.getContextualReferenceByName(beanManager, nameFactory
                .generateRoleBeanName(roles[0].name()), GenericRoleVoter.class);
    }

    @Produces
    public NamedApplicationRole getRole(InjectionPoint injectionPoint) {
        Annotation annotation = injectionPoint.getAnnotated().getAnnotation(config.getNamedRoleCheckClass());
        if (annotation == null) {
            throw new UnsatisfiedResolutionException(
                    "Injection points for NamedApplicationRole needs an additional " + config.getNamedPermissionCheck() +
                            " annotation to determine the correct bean");
        }
        NamedRole[] roles = AnnotationUtil.getRoleValues(annotation);
        if (roles.length>1) {
            throw new AmbiguousResolutionException("Only one named role can be specified.");
        }

        return lookup.getRole(roles[0].name());

    }

}
