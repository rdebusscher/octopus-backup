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
package be.c4j.ee.security.permission;

import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import org.apache.myfaces.extensions.cdi.core.api.security.AbstractAccessDecisionVoter;
import org.apache.myfaces.extensions.cdi.core.api.security.SecurityViolation;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.subject.Subject;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.interceptor.InvocationContext;
import java.util.Set;

@Typed
public class GenericPermissionVoter extends AbstractAccessDecisionVoter {

    @Inject
    private Subject subject;

    private NamedDomainPermission namedPermission;

    public void setNamedPermission(NamedDomainPermission someNamedPermission) {
        namedPermission = someNamedPermission;
    }

    @Override
    protected void checkPermission(InvocationContext invocationContext, Set<SecurityViolation> violations) {
        try {
            subject.checkPermission(namedPermission);
        } catch (AuthorizationException e) {
            SecurityViolationInfoProducer infoProducer = CodiUtils.getContextualReferenceByClass(SecurityViolationInfoProducer.class);
            violations.add(newSecurityViolation(infoProducer.getViolationInfo(invocationContext, namedPermission)));
        }

    }

    /*
    FIXME
    New issue 6
    boolean verifyPermission
    catch and return false
    */
}
