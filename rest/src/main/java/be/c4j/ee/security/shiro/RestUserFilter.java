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

import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import org.apache.shiro.web.filter.authc.UserFilter;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
public class RestUserFilter extends UserFilter {

    /**
     * Overrides the default behavior to show and swallow the exception if the exception is
     * {@link org.apache.shiro.authz.UnauthenticatedException}.
     */
    @Override
    protected void cleanup(ServletRequest request, ServletResponse response, Exception existing) throws ServletException, IOException {
        Exception exception = existing;
        Throwable unauthorized = OctopusUnauthorizedException.getUnauthorizedException(exception);
        if (unauthorized != null) {
            try {
                ((HttpServletResponse) response).setStatus(401);
                response.getOutputStream().println(unauthorized.getMessage());
                existing = null;
            } catch (Exception e) {
                exception = e;
            }
        }
        super.cleanup(request, response, exception);

    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return true;  // Let the chain continue, other filters can handle it and authenticate based on the parameters.
    }
}
