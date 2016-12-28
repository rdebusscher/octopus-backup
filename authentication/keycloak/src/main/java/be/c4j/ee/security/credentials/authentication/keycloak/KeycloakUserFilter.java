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
package be.c4j.ee.security.credentials.authentication.keycloak;

import be.c4j.ee.security.authentication.ActiveSessionRegistry;
import be.c4j.ee.security.shiro.OctopusUserFilter;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Initializable;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 *
 */
public class KeycloakUserFilter extends OctopusUserFilter implements Initializable {

    private ActiveSessionRegistry activeSessionRegistry;

    @Override
    public String getLoginUrl() {
        return "/keycloak";
    }

    @Override
    public void init() throws ShiroException {
        activeSessionRegistry = BeanProvider.getContextualReference(ActiveSessionRegistry.class);
    }

    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        if (isLoginRequest(request, response)) {
            return true;
        } else {
            Subject subject = getSubject(request, response);
            // If principal is not null, then the user is known and should be allowed access.
            boolean accessAllowed = subject.getPrincipal() != null;
            if (accessAllowed) {
                accessAllowed = activeSessionRegistry.isSessionActive(subject.getPrincipal());
            }

            return accessAllowed;
        }
    }

}