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
package be.c4j.ee.security.filter;

import be.c4j.ee.security.exception.OctopusUnexpectedException;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 */

public class ExceptionFilter extends AdviceFilter {

    @Override
    protected void cleanup(ServletRequest request, ServletResponse response, Exception existing) throws ServletException, IOException {
        Exception exception = existing;
        if (exception != null) {
            Throwable unexpectedException = getUnexpectedException(existing);

            Logger logger = LoggerFactory.getLogger(ExceptionFilter.class);
            logger.error(exception.getCause().getMessage(), exception.getCause());

            Boolean sessionCreationEnabled = (Boolean) request.getAttribute(DefaultSubjectContext.SESSION_CREATION_ENABLED);

            if (sessionCreationEnabled != null && !sessionCreationEnabled) {
                // We assume we are in a REST/JAX_RS call and thus return JSON
                HttpServletResponse servletResponse = (HttpServletResponse) response;
                servletResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

                String code = unexpectedException == null ? "OCT-001" : "OCT-002";
                ErrorInfo info = new ErrorInfo(code, exception.getMessage());

                servletResponse.getWriter().print(info.toJSON());

                exception = null;
            } else {
                // Since we are in a finally block, this exception takes over and thus erasing all information we have about stacktraces
                // OWASP A6
                throw new OctopusUnexpectedException("Something went wrong");
            }
        }
        super.cleanup(request, response, null);
    }

    private Throwable getUnexpectedException(Throwable exception) {
        if (exception instanceof OctopusUnexpectedException) {
            return exception;
        } else {
            if (exception == null) {
                return null;
            }
            return getUnexpectedException(exception.getCause());
        }
    }
}
