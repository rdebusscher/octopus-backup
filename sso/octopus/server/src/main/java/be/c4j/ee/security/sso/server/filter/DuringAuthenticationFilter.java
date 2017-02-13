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

import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import be.c4j.ee.security.sso.server.config.SSOServerConfiguration;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.web.filter.authc.UserFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
public class DuringAuthenticationFilter extends UserFilter {

    private SSODataEncryptionHandler encryptionHandler;

    @Override
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
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

        if (!result) {
            showErrorMessage((HttpServletResponse) response);
        } else {
            result = super.onPreHandle(request, response, mappedValue);
        }
        return result;
    }

    private void showErrorMessage(HttpServletResponse response) throws IOException {
        response.reset();
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        httpServletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        httpServletResponse.setContentType("text/plain");
        httpServletResponse.getWriter().write("Missing some required parameter. Is Octopus SSO Client correctly configured?");
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        boolean result = super.isAccessAllowed(request, response, mappedValue);
        if (!result) {
            result = tryAuthenticationFromCookie((HttpServletRequest) request, (HttpServletResponse) response);
        }
        return result;
    }

    private boolean tryAuthenticationFromCookie(HttpServletRequest request, HttpServletResponse resp) {
        boolean result = false;
        SSOTokenStore tokenStore = BeanProvider.getContextualReference(SSOTokenStore.class);

        OctopusSSOUser user = tokenStore.getUser(getSSOTokenCookie(request));
        if (user != null) {
            try {
                SecurityUtils.getSubject().login(user);
                result = true;
            } catch (AuthenticationException e) {

            }

        }
        return result;
    }


    private String getSSOTokenCookie(ServletRequest request) {
        String result = null;

        SSOServerConfiguration ssoServerConfiguration = BeanProvider.getContextualReference(SSOServerConfiguration.class);
        String cookieName = ssoServerConfiguration.getSSOCookieName();
        HttpServletRequest servletRequest = (HttpServletRequest) request;
        Cookie[] cookies = servletRequest.getCookies();
        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                result = cookie.getValue();
            }
        }
        return result;
    }
}
