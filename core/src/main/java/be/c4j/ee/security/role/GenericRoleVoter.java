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
 *
 */
package be.c4j.ee.security.role;

import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.deltaspike.security.api.authorization.AbstractAccessDecisionVoter;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.subject.Subject;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import java.util.Set;

/**
 *
 */
@Typed
public class GenericRoleVoter extends AbstractAccessDecisionVoter {

    @Inject
    private Subject subject;

    private NamedApplicationRole namedRole;

    public void setNamedRole(NamedApplicationRole namedRole) {
        this.namedRole = namedRole;
    }

    @Override
    protected void checkPermission(AccessDecisionVoterContext accessDecisionVoterContext, Set<SecurityViolation> violations) {
        try {
            subject.checkPermission(namedRole);
        } catch (AuthorizationException e) {
            SecurityViolationInfoProducer infoProducer = BeanProvider.getContextualReference(SecurityViolationInfoProducer.class);
            violations.add(newSecurityViolation(infoProducer.getViolationInfo(accessDecisionVoterContext, namedRole)));

        }

    }

    public boolean verifyPermission() {
        boolean result = true;
        try {
            subject.checkPermission(namedRole);
        } catch (AuthorizationException e) {
            result = false;
        }
        return result;
    }
}