/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.interceptor.checks;

import be.c4j.ee.security.context.OctopusSecurityContext;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.systemaccount.SystemAccount;
import be.c4j.ee.security.systemaccount.SystemAccountPrincipal;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.shiro.subject.Subject;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.lang.annotation.Annotation;
import java.util.Arrays;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class SecurityCheckSystemAccountCheck implements SecurityCheck {

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, Annotation securityAnnotation) {
        SecurityCheckInfo result;

        SystemAccount systemAccount = (SystemAccount) securityAnnotation;

        List<String> identifiers = Arrays.asList(systemAccount.value());

        Object principal = subject.getPrincipal();
        if (OctopusSecurityContext.isSystemAccount(principal)) {

            if (subject.isAuthenticated()) {
                SystemAccountPrincipal systemAccountPrincipal = (SystemAccountPrincipal) principal;
                if (identifiers.contains(systemAccountPrincipal.getIdentifier())) {
                    result = SecurityCheckInfo.allowAccess();
                } else {
                    result = SecurityCheckInfo.withException(new OctopusUnauthorizedException("System account '" + systemAccountPrincipal.getIdentifier() + "' not allowed",
                            infoProducer.getViolationInfo(accessContext)));
                }
            } else {
                result = SecurityCheckInfo.withException(new OctopusUnauthorizedException("Authenticated System account required", infoProducer.getViolationInfo(accessContext)));
            }
        } else {
            result = SecurityCheckInfo.withException(new OctopusUnauthorizedException("System account required", infoProducer.getViolationInfo(accessContext)));
        }
        return result;
    }

    @Override
    public boolean hasSupportFor(Object annotation) {
        return SystemAccount.class.isAssignableFrom(annotation.getClass());
    }
}
