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
package be.c4j.ee.security.custom;

import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.util.MethodParameterCheckUtil;
import org.apache.deltaspike.security.api.authorization.AbstractAccessDecisionVoter;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.apache.shiro.subject.Subject;

import javax.inject.Inject;
import javax.interceptor.InvocationContext;
import javax.servlet.http.HttpServletRequest;
import java.util.Set;

/**
 *
 */
@PublicAPI
public abstract class AbstractGenericVoter extends AbstractAccessDecisionVoter {

    @Inject
    protected MethodParameterCheckUtil methodParameterCheckUtil;

    @Inject
    protected SecurityViolationInfoProducer infoProducer;

    @Inject
    protected UserPrincipal userPrincipal;

    @Inject
    protected Subject subject;

    protected void checkMethodHasParameterTypes(Set<SecurityViolation> violations, InvocationContext invocationContext, Class<?>... parameterTypes) {
        SecurityViolation violation = methodParameterCheckUtil.checkMethodHasParameterTypes(invocationContext, parameterTypes);
        if (violation != null) {
            violations.add(violation);
        }
    }

    protected boolean verifyMethodHasParameterTypes(InvocationContext invocationContext, Class<?>... parameterTypes) {
        SecurityViolation violation = methodParameterCheckUtil.checkMethodHasParameterTypes(invocationContext, parameterTypes);
        return violation == null;
    }

    protected boolean hasServletRequestInfo(InvocationContext invocationContext) {
        SecurityViolation violation = methodParameterCheckUtil.checkMethodHasParameterTypes(invocationContext, HttpServletRequest.class);
        return violation == null;
    }

    protected String getURLRequestParameter(InvocationContext invocationContext, String paramName) {
        HttpServletRequest httpServletRequest = methodParameterCheckUtil.getAssignableParameter(invocationContext, HttpServletRequest.class);
        return httpServletRequest.getParameter(paramName);
    }

    public boolean verify(AccessDecisionVoterContext invocationContext) {
        return checkPermission(invocationContext).isEmpty();
    }
}
