/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.credentials.authentication.cas;

import be.c4j.ee.security.authentication.ActiveSessionRegistry;
import be.c4j.ee.security.credentials.authentication.cas.config.CasConfiguration;
import be.c4j.ee.security.shiro.OctopusUserFilter;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Initializable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
public class CasUserFilter extends OctopusUserFilter implements Initializable {

    private static final Logger LOGGER = LoggerFactory.getLogger(CasUserFilter.class);

    private CasConfiguration casConfiguration;
    private ActiveSessionRegistry activeSessionRegistry;

    private boolean loginUrlDefined = false;
    private String casService;

    @Override
    public void init() throws ShiroException {
        casConfiguration = BeanProvider.getContextualReference(CasConfiguration.class);
        activeSessionRegistry = BeanProvider.getContextualReference(ActiveSessionRegistry.class);
    }

    @Override
    protected boolean isLoginRequest(ServletRequest request, ServletResponse response) {
        if (!loginUrlDefined) {
            defineLoginURL((HttpServletRequest) request);
            loginUrlDefined = true;
            LOGGER.info("CAS service = " + casService);
            casConfiguration.setCasService(casService);
        }
        return super.isLoginRequest(request, response);
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

    private void defineLoginURL(HttpServletRequest request) {
        StringBuilder result = new StringBuilder();
        String ssoServer = casConfiguration.getSSOServer();
        result.append(ssoServer);
        if (!ssoServer.endsWith("/")) {
            result.append("/");
        }
        result.append("login?service=");

        casService = assembleCallbackUrl(request);
        result.append(casService);

        setLoginUrl(result.toString());
    }

    private String assembleCallbackUrl(HttpServletRequest req) {
        StringBuilder result = new StringBuilder();
        result.append(req.getScheme()).append("://");
        result.append(req.getServerName()).append(':');
        result.append(req.getServerPort());
        result.append(req.getContextPath()).append("/cas-callback");
        return result.toString();
    }

}

