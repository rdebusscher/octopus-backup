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
package be.c4j.ee.security.interceptor.checks;

import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.exception.SecurityViolationInfoProducer;
import be.c4j.ee.security.realm.OnlyDuringAuthorization;
import be.c4j.ee.security.util.SpecialStateChecker;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.shiro.subject.Subject;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.lang.annotation.Annotation;

/**
 *
 */
@ApplicationScoped
public class SecurityCheckOnlyDuringAuthorization implements SecurityCheck {

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, Annotation securityAnnotation) {
        SecurityCheckInfo result;
        // No longer perform the check on subject.getPrincipal() in case we wan't to log on when another user is already logged on (and no logout is done)
        if (!SpecialStateChecker.isInAuthorization()) {
            result = SecurityCheckInfo.withException(
                    new OctopusUnauthorizedException("Execution of method only allowed during authorization process"
                            , infoProducer.getViolationInfo(accessContext)));
        } else {
            result = SecurityCheckInfo.allowAccess();
        }

        return result;
    }

    @Override
    public boolean hasSupportFor(Object annotation) {
        return OnlyDuringAuthorization.class.isAssignableFrom(annotation.getClass());
    }
}
