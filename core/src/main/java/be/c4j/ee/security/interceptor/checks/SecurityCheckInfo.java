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
package be.c4j.ee.security.interceptor.checks;

import be.c4j.ee.security.exception.OctopusUnauthorizedException;

/**
 *
 */
public class SecurityCheckInfo {

    private boolean accessAllowed;
    private OctopusUnauthorizedException exception;

    private SecurityCheckInfo() {
    }

    public static SecurityCheckInfo allowAccess() {
        SecurityCheckInfo result = new SecurityCheckInfo();
        result.accessAllowed = true;
        return result;
    }

    public static SecurityCheckInfo withException(OctopusUnauthorizedException exception) {
        SecurityCheckInfo result = new SecurityCheckInfo();
        result.accessAllowed = false;
        result.exception = exception;
        return result;
    }

    public boolean isAccessAllowed() {
        return accessAllowed;
    }

    public OctopusUnauthorizedException getException() {
        return exception;
    }
}
