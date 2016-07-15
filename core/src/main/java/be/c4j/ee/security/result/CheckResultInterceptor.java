/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.result;

import be.c4j.ee.security.CustomAccessDecissionVoterContext;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.deltaspike.security.api.authorization.AbstractAccessDecisionVoter;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 *
 */
@Interceptor
@CheckResult
public class CheckResultInterceptor implements Serializable {

    @AroundInvoke
    public Object interceptResult(InvocationContext context) throws Exception {
        // First find the CheckResultVoter, throws exception if not present
        CheckResultVoter checkResultVoter = getCheckResultVoter(context);

        Object result = context.proceed();

        AccessDecisionVoterContext voterContext = new CustomAccessDecissionVoterContext(null, new Object[]{result});

        Set<SecurityViolation> violations = checkWithVoters(checkResultVoter, voterContext);

        if (!violations.isEmpty()) {
            throw new OctopusUnauthorizedException(violations);
        }

        return result;
    }

    private Set<SecurityViolation> checkWithVoters(CheckResultVoter checkResultVoter, AccessDecisionVoterContext voterContext) {
        Set<SecurityViolation> violations = new HashSet<SecurityViolation>();
        for (Class<? extends AbstractAccessDecisionVoter> clsName : checkResultVoter.value()) {
            AbstractAccessDecisionVoter voter = BeanProvider.getContextualReference(clsName);
            violations.addAll(voter.checkPermission(voterContext));
        }
        return violations;
    }

    private CheckResultVoter getCheckResultVoter(InvocationContext context) {
        CheckResultVoter checkResultVoter = context.getMethod().getAnnotation(CheckResultVoter.class);
        if (checkResultVoter == null) {
            throw new CheckResultUsageException(context.getMethod().toGenericString());
        }
        return checkResultVoter;
    }
}
