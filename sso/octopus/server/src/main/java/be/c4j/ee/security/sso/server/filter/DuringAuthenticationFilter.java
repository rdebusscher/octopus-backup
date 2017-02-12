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
package be.c4j.ee.security.sso.server.filter;

import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.web.filter.PathMatchingFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 */
public class DuringAuthenticationFilter extends PathMatchingFilter {

    private SSODataEncryptionHandler encryptionHandler;

    @Override
    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        // We can't use the init (and Initializable ) because it get called during initialization.
        if (encryptionHandler == null) {
            encryptionHandler = BeanProvider.getContextualReference(SSODataEncryptionHandler.class, true);
        }

        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String application = httpServletRequest.getParameter("application");

        boolean result = true;
        if (application == null || application.trim().isEmpty()) {
            result = false;
        }
        if (result && encryptionHandler != null) {

            result = encryptionHandler.validate(httpServletRequest);
        }
        return result;
    }

    @Override
    protected void postHandle(ServletRequest request, ServletResponse response) throws Exception {
        response.reset();
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        httpServletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        httpServletResponse.setContentType("text/plain");
        httpServletResponse.getWriter().write("Missing some required parameter. Is Octopus SSO Client correctly configured?");
    }
}
