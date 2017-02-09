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
package be.c4j.ee.security.exception;

import be.c4j.ee.security.exception.violation.BasicAuthorizationViolation;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authz.UnauthorizedException;

import java.util.Set;

/**
 *
 */
public class OctopusUnauthorizedException extends UnauthorizedException {

    private String message;
    private String exceptionPointInfo;

    public OctopusUnauthorizedException(String violation, String exceptionPointInfo) {
        message = violation;
        this.exceptionPointInfo = exceptionPointInfo;
    }

    public OctopusUnauthorizedException(Set<SecurityViolation> securityViolations) {
        StringBuilder violations = new StringBuilder();
        violations.append("Violation of ");
        boolean first = true;
        String violationName;
        String info;
        for (SecurityViolation violation : securityViolations) {
            if (!first) {
                violations.append(" - ");
            }
            // TODO Review this logic
            if (violation instanceof BasicAuthorizationViolation) {
                BasicAuthorizationViolation basicViolation = (BasicAuthorizationViolation) violation;
                violationName = basicViolation.getReason();
                info = basicViolation.getExceptionPoint();
            } else {
                if (violation.getReason().contains("@")) {
                    String[] parts = violation.getReason().split("@", 2);
                    violationName = parts[0];
                    info = parts[1];

                } else {
                    violationName = violation.getReason();
                    info = null;
                }
            }
            violations.append(violationName);
            if (exceptionPointInfo == null && info != null) {
                exceptionPointInfo = info;
            }
            first = false;
        }
        message = violations.toString();
    }

    public String getMessage() {
        return message;
    }

    public String getExceptionPointInfo() {
        return exceptionPointInfo;
    }

    public static Throwable getUnauthorizedException(Throwable someException) {
        Throwable result = null;
        if (someException != null) {
            if (someException instanceof UnauthorizedException || someException instanceof AccountException || someException instanceof AuthenticationException) {
                result = someException;
            } else {
                if (someException.getCause() != null) {
                    result = getUnauthorizedException(someException.getCause());
                }
            }
        }
        return result;
    }
}
