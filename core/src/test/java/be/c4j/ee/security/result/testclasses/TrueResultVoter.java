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
package be.c4j.ee.security.result.testclasses;

import be.c4j.ee.security.OctopusInvocationContext;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import org.apache.deltaspike.security.api.authorization.AbstractAccessDecisionVoter;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import java.util.Set;

/**
 *
 */
public class TrueResultVoter extends AbstractAccessDecisionVoter {
    @Override
    protected void checkPermission(AccessDecisionVoterContext accessDecisionVoterContext, Set<SecurityViolation> violations) {
        OctopusInvocationContext invocationContext = accessDecisionVoterContext.getSource();
        Object[] parameters = invocationContext.getParameters();
        if (!(Boolean) parameters[0]) {
            throw new OctopusUnauthorizedException("value must be true", null);
        }
    }
}
