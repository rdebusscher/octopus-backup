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
package be.c4j.ee.security.exception;

import org.apache.myfaces.extensions.cdi.core.api.security.SecurityViolation;
import org.apache.shiro.authz.UnauthorizedException;

import java.util.Set;

/**
 *
 */
public class OctopusUnauthorizedException extends UnauthorizedException {

    private StringBuilder violations;
    private String exceptionPointInfo;

    public OctopusUnauthorizedException(String violation, String exceptionPointInfo) {
        violations = new StringBuilder();
        violations.append(violation);
        this.exceptionPointInfo = exceptionPointInfo;
    }

    public OctopusUnauthorizedException(Set<SecurityViolation> securityViolations) {
        violations = new StringBuilder();
        violations.append("Violation of ");
        boolean first = true;
        String violationName;
        String info;
        for (SecurityViolation violation : securityViolations) {
            if (violation.getReason().contains("@")) {
                String[] parts = violation.getReason().split("@", 2);
                violationName = parts[0];
                info = parts[1];

            } else {
                violationName = violation.getReason();
                info = null;
            }
            if (!first) {
                violations.append(" - ");
            }
            violations.append(violationName);
            if (exceptionPointInfo == null && info != null) {
                exceptionPointInfo = info;
            }
            first = false;
        }
    }

    public String getMessage() {
        return violations.toString();
    }

    public String getExceptionPointInfo() {
        return exceptionPointInfo;
    }
}
