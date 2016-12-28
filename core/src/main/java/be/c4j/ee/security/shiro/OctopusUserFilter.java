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
package be.c4j.ee.security.shiro;

import be.c4j.ee.security.config.OctopusConfig;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.UserFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 *
 */
public class OctopusUserFilter extends UserFilter {

    private static final String FACES_REDIRECT_XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<partial-response><redirect url=\"%s\"></redirect></partial-response>";

    @Override
    protected void redirectToLogin(ServletRequest req, ServletResponse res) throws IOException {
        HttpServletRequest request = (HttpServletRequest) req;

        if ("partial/ajax".equals(request.getHeader("Faces-Request"))) {
            res.setContentType("text/xml");
            res.setCharacterEncoding("UTF-8");

            String loginUrl = getLoginUrl();
            if (loginUrl.startsWith("/") || !loginUrl.startsWith("http")) {
                // If it is a relative URL, use the context path.
                loginUrl = request.getContextPath() + loginUrl;
            }
            res.getWriter().printf(FACES_REDIRECT_XML, loginUrl);
        } else {
            super.redirectToLogin(req, res);
        }
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        OctopusConfig config = BeanProvider.getContextualReference(OctopusConfig.class);
        Boolean postIsAllowedSavedRequest = Boolean.valueOf(config.getPostIsAllowedSavedRequest());

        HttpServletRequest req = (HttpServletRequest) request;
        if ("POST".equals(req.getMethod()) && !postIsAllowedSavedRequest) {
            redirectToLogin(request, response);
            return false;
        } else {
            return super.onAccessDenied(request, response);
        }
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        if (isLoginRequest(request, response)) {
            return true;
        } else {
            Subject subject = getSubject(request, response);
            // If principal is not null, then the user is known and should be allowed access.
            return subject.getPrincipal() != null && subject.isAuthenticated();
        }
    }
}
