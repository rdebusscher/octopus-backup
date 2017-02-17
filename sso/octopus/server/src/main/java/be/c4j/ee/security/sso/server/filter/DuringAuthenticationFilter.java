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

import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.shiro.OctopusUserFilter;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import be.c4j.ee.security.sso.server.ApplicationCallback;
import be.c4j.ee.security.sso.server.config.SSOServerConfiguration;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.web.filter.authc.UserFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private OctopusUserFilter octopusUserFilter;

    private OctopusConfig octopusConfig;

    private Logger logger;

    @Override
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        // We can't use the init (and Initializable ) because it get called during initialization.
        if (encryptionHandler == null) {
            encryptionHandler = BeanProvider.getContextualReference(SSODataEncryptionHandler.class, true);
        }

        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String application = httpServletRequest.getParameter("application");

        String realApplication = application;
        boolean result = true;

        if (application == null || application.trim().isEmpty()) {
            // Application query parameter is required
            result = false;
        }

        if (result && encryptionHandler != null) {
            // If we have encryptionHandler, the application must be checked by encryptionHandler
            String apiKey = null;
            if (encryptionHandler.requiresApiKey()) {
                // If encryptionHandler needs apiKey, then get the value
                apiKey = httpServletRequest.getParameter("x-api-key");
            }
            // Validate
            result = encryptionHandler.validate(apiKey, application);

            if (result) {
                // Decrypt the value
                realApplication = encryptionHandler.decryptData(application, apiKey);
            }
        }

        // Check to see if the application is configured
        if (result) {
            ApplicationCallback applicationCallback = BeanProvider.getContextualReference(ApplicationCallback.class);
            String callback = applicationCallback.determineCallback(realApplication);
            if (callback == null || callback.isEmpty()) {
                result = false;
            }
        }


        if (!result) {
            showErrorMessage((HttpServletResponse) response);
        } else {
            // Here we do the default login, including a redirect to login if needed or authenticate from cookie.
            result = super.onPreHandle(request, response, mappedValue);
        }
        return result;
    }

    private void showErrorMessage(HttpServletResponse response) throws IOException {
        response.reset();
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType("text/plain");
        response.getWriter().write("Missing some required parameter(s) or configuration. Is Octopus SSO Client and Server correctly configured?");
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

        String realToken = getSSOTokenCookie(request);
        OctopusSSOUser user = tokenStore.getUser(realToken);

        if (user != null && !realToken.equals(user.getToken())) {
            logger.warn("Token used as key in tokenStore returned a SSOUser with a different Token ");
        }

        if (user != null) {
            try {
                SecurityUtils.getSubject().login(user);
                result = true;

                showDebugInfo(user);
            } catch (AuthenticationException e) {

            }

        }
        return result;
    }

    private void showDebugInfo(OctopusSSOUser user) {
        if (octopusConfig == null) {
            octopusConfig = BeanProvider.getContextualReference(OctopusConfig.class);
            logger = LoggerFactory.getLogger(DuringAuthenticationFilter.class);
        }

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("User %s is authenticated from SSO Cookie %s", user.getFullName(), user.getToken()));
        }
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

    @Override
    protected boolean isLoginRequest(ServletRequest request, ServletResponse response) {
        octopusUserFilter.prepareLoginURL(request, response);
        return super.isLoginRequest(request, response);
    }

    @Override
    public String getLoginUrl() {
        return octopusUserFilter.getLoginUrl();
    }

    public OctopusUserFilter getUserFilter() {
        return octopusUserFilter;
    }

    public void setUserFilter(OctopusUserFilter userFilter) {
        this.octopusUserFilter = userFilter;
    }
}
