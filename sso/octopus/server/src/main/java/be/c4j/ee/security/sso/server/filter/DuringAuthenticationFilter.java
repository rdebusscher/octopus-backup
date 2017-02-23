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

import be.c4j.ee.security.shiro.OctopusUserFilter;
import be.c4j.ee.security.sso.SSOFlow;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import be.c4j.ee.security.sso.server.client.ClientInfo;
import be.c4j.ee.security.sso.server.client.ClientInfoRetriever;
import be.c4j.ee.security.sso.server.cookie.SSOHelper;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authc.UserFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
public class DuringAuthenticationFilter extends UserFilter implements Initializable {

    private SSODataEncryptionHandler encryptionHandler;

    private OctopusUserFilter octopusUserFilter;

    private SSOHelper ssoHelper;

    @Override
    public void init() throws ShiroException {
        ssoHelper = BeanProvider.getContextualReference(SSOHelper.class);
    }

    @Override
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        // We can't use the init (and Initializable ) because it get called during initialization.
        if (encryptionHandler == null) {
            encryptionHandler = BeanProvider.getContextualReference(SSODataEncryptionHandler.class, true);
        }

        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String clientId = httpServletRequest.getParameter("client_id");
        String responseType = httpServletRequest.getParameter("response_type");

        boolean result = true;

        if (clientId == null || clientId.trim().isEmpty()) {
            // client query parameter is required
            result = false;
        }

        if (responseType != null && responseType.trim().length() > 1) {
            // If response_type is specified, it need to be a valid value.
            // But logout for example doesn't need to parameter.
            SSOFlow ssoFlow = SSOFlow.defineFlow(responseType);
            if (ssoFlow == null) {
                // response_type query parameter is required and needs to be a valid value
                result = false;
            }
        }

        // Check to see if the application is configured
        if (result) {
            ClientInfoRetriever clientInfoRetriever = BeanProvider.getContextualReference(ClientInfoRetriever.class);
            ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(clientId);
            if (clientInfo == null || clientInfo.getCallbackURL() == null || clientInfo.getCallbackURL().isEmpty()) {
                result = false;
            }
        }


        if (!result) {
            showErrorMessage((HttpServletResponse) response);
        } else {
            ssoHelper.markAsSSOLogin(httpServletRequest, clientId);

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
    protected boolean isLoginRequest(ServletRequest request, ServletResponse response) {
        octopusUserFilter.prepareLoginURL(request, response);
        return super.isLoginRequest(request, response);
    }

    @Override
    public String getLoginUrl() {
        return octopusUserFilter.getLoginUrl();
    }

    // TODO Probably not need, setter is for the definition with shiro.ini
    public OctopusUserFilter getUserFilter() {
        return octopusUserFilter;
    }

    public void setUserFilter(OctopusUserFilter userFilter) {
        this.octopusUserFilter = userFilter;
    }
}
