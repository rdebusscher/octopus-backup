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
package be.c4j.ee.security.shiro;

import be.c4j.ee.security.systemaccount.SystemAccountPrincipal;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.mgt.DefaultWebSessionStorageEvaluator;
import org.apache.shiro.web.subject.support.WebDelegatingSubject;

/**
 *
 */

public class OctopusSessionStorageEvaluator extends DefaultWebSessionStorageEvaluator {

    public static final String NO_STORAGE = "octopusNoStorage";

    @Override
    public boolean isSessionStorageEnabled(Subject subject) {
        boolean result;
        if (subject.getPrincipal() instanceof SystemAccountPrincipal) {
            result = false;
        } else {
            result = true;
            if (subject instanceof WebDelegatingSubject) {

                WebDelegatingSubject webSubject = (WebDelegatingSubject) subject;
                Object noStorageParameter = webSubject.getServletRequest().getAttribute(NO_STORAGE);
                if (noStorageParameter != null && (Boolean) noStorageParameter) {
                    result = false;
                }
            }

            if (result) {
                result = super.isSessionStorageEnabled(subject);
            }
        }
        return result;
    }
}
