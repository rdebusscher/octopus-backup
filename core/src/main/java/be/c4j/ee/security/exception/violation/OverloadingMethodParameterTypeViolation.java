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
package be.c4j.ee.security.exception.violation;

import java.util.List;

/**
 * When custom AbstractGenericVoter can work with different types of method parameters. But none of the expected Types is found.
 *
 */
public class OverloadingMethodParameterTypeViolation extends BasicAuthorizationViolation {

    private String reason;

    public OverloadingMethodParameterTypeViolation(String exceptionPoint, List<Class<?>> missingParameterTypes) {
        super(null, exceptionPoint);
        this.reason = getInfoAboutMissingParameterTypes(missingParameterTypes);
    }

    @Override
    public String getReason() {
        return reason;
    }

    private String getInfoAboutMissingParameterTypes(List<Class<?>> missingParameterTypes) {
        StringBuilder result = new StringBuilder();
        result.append("Method needs to have a parameter of one of the following types :");
        boolean first = true;
        for (Class<?> type : missingParameterTypes) {
            if (!first) {
                result.append(", ");
            }
            result.append(type.getName());
            first = false;
        }
        return result.toString();
    }
}
