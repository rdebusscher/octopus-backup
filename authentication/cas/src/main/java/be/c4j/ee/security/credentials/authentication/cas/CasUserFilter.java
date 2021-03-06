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
package be.c4j.ee.security.credentials.authentication.cas;

import be.c4j.ee.security.shiro.OctopusUserFilter;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Initializable;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
public class CasUserFilter extends OctopusUserFilter implements Initializable {

    private CasConfigurationHelper casConfigurationHelper;

    @Override
    public void init() throws ShiroException {
        casConfigurationHelper = BeanProvider.getContextualReference(CasConfigurationHelper.class);
    }

    @Override
    public void prepareLoginURL(ServletRequest request, ServletResponse response) {
        String loginURL = casConfigurationHelper.defineCasLoginURL((HttpServletRequest) request);
        setLoginUrl(loginURL);
    }

    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        if (isLoginRequest(request, response)) {
            return true;
        } else {
            Subject subject = getSubject(request, response);
            // If principal is not null, then the user is known and should be allowed access.
            boolean accessAllowed = subject.getPrincipal() != null && subject.isAuthenticated();
            /*
            FIXME Disabled as not working in a load balanced environment.
            // TODO And what was the idea to have an additional check when user is already allowed.
            // This userFilter is also used to retrieve octopus SSO User info when SSO server delegates to CAS.
            // So we need a 'simple' user filter or JAX-RS specific one.
            // Fix in 0.9.8.
            if (accessAllowed) {
                // TODO I think this kind of logic needs also be used in other UserFilters like OAuth2UserFilter
                accessAllowed = activeSessionRegistry.isSessionActive(subject.getPrincipal());
            }
            */

            return accessAllowed;
        }
    }

}

