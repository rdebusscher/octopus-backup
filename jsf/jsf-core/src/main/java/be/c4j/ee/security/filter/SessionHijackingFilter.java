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

import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.config.SessionHijackingLevel;
import be.c4j.ee.security.session.ApplicationUsageController;
import be.c4j.ee.security.session.ApplicationUsageInfo;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 */
public class SessionHijackingFilter extends AdviceFilter implements Initializable {

    public static final String OCTOPUS_SESSION_HIJACKING_ATTEMPT = "OctopusSessionHijackingAttempt";

    private ApplicationUsageController applicationUsageController;

    private OctopusJSFConfig jsfConfig;

    @Override
    public void init() throws ShiroException {
        applicationUsageController = BeanProvider.getContextualReference(ApplicationUsageController.class);
        jsfConfig = BeanProvider.getContextualReference(OctopusJSFConfig.class);
    }

    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        boolean result = true;
        if (jsfConfig.getSessionHijackingLevel() != SessionHijackingLevel.OFF) {
            HttpServletRequest httpServletRequest = (HttpServletRequest) request;

            if (!WebUtils._isSessionCreationEnabled(httpServletRequest)) {
                // probably we are using REST Endpoints also available within the app and since we don't have any session, we can't Hijack it :)
                return true;
            }

            ApplicationUsageInfo info = applicationUsageController.getInfo(httpServletRequest);

            String userAgent = httpServletRequest.getHeader("User-Agent");
            result = info.getUserAgent().equals(userAgent);

            if (result && jsfConfig.getSessionHijackingLevel() == SessionHijackingLevel.ON) {

                String remoteHost = request.getRemoteAddr();
                result = info.getRemoteHost().equals(remoteHost);
            }

            if (!result) {
                // Session Hijacking detected, so stop this request and inform other session.
                HttpServletResponse servletResponse = (HttpServletResponse) response;
                servletResponse.setStatus(401);
                servletResponse.getWriter().write("Refused by the Session Hijacking Protection");

                info.getHttpSession().setAttribute(OCTOPUS_SESSION_HIJACKING_ATTEMPT, Boolean.TRUE);
            }
        }

        return result;

    }
}
