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
import be.c4j.ee.security.permission.GenericPermissionVoter;
import be.c4j.ee.security.permission.NamedDomainPermission;
import be.c4j.ee.security.permission.NamedPermission;
import be.c4j.ee.security.permission.PermissionLookup;
import be.c4j.ee.security.util.AnnotationUtil;
import be.c4j.ee.security.util.CDIUtil;
import org.apache.myfaces.extensions.cdi.core.api.provider.BeanManagerProvider;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.AmbiguousResolutionException;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.UnsatisfiedResolutionException;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.inject.Inject;
import java.lang.annotation.Annotation;

@ApplicationScoped
public class NamedPermissionProducer {

    @Inject
    private OctopusConfig config;

    @Inject
    private VoterNameFactory nameFactory;

    private PermissionLookup<? extends NamedPermission> lookup;

    @PostConstruct
    public void init() {
        lookup = CDIUtil.getBeanManually(PermissionLookup.class);
    }

    @Produces
    public GenericPermissionVoter getVoter(InjectionPoint injectionPoint) {
        Annotation annotation = injectionPoint.getAnnotated().getAnnotation(config.getNamedPermissionCheckClass());
        if (annotation == null) {
            throw new UnsatisfiedResolutionException(
                    "Injection points for GenericPermissionVoter needs an additional " + config.getNamedPermissionCheck() +
                            " annotation to determine the correct bean"
            );
        }
        NamedPermission[] permissions = AnnotationUtil.getPermissionValues(annotation);
        if (permissions.length > 1) {
            throw new AmbiguousResolutionException("Only one named permission can be specified.");
        }


        return CodiUtils.getContextualReferenceByName(BeanManagerProvider.getInstance().getBeanManager(), nameFactory
                .generatePermissionBeanName(permissions[0].name()), GenericPermissionVoter.class);
    }

    @Produces
    public NamedDomainPermission getPermission(InjectionPoint injectionPoint) {
        Annotation annotation = injectionPoint.getAnnotated().getAnnotation(config.getNamedPermissionCheckClass());
        if (annotation == null) {
            throw new UnsatisfiedResolutionException(
                    "Injection points for NamedDomainPermission needs an additional " + config.getNamedPermissionCheck() +
                            " annotation to determine the correct bean"
            );
        }
        NamedPermission[] permissions = AnnotationUtil.getPermissionValues(annotation);
        if (permissions.length > 1) {
            throw new AmbiguousResolutionException("Only one named permission can be specified.");
        }

        return lookup.getPermission(permissions[0].name());

    }

}
