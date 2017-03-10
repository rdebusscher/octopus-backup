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
import be.c4j.ee.security.sso.server.client.ClientInfo;
import be.c4j.ee.security.sso.server.client.ClientInfoRetriever;
import be.c4j.ee.security.sso.server.cookie.SSOHelper;
import be.c4j.ee.security.sso.server.token.OIDCEndpointToken;
import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.ShiroException;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authc.UserFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

/**
 *
 */
public class OIDCEndpointFilter extends UserFilter implements Initializable {

    private OctopusUserFilter octopusUserFilter;

    private SSOHelper ssoHelper;

    @Override
    public void init() throws ShiroException {
        ssoHelper = BeanProvider.getContextualReference(SSOHelper.class);
    }

    @Override
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {

        HttpServletRequest httpServletRequest = (HttpServletRequest) request;

        String requestURI = httpServletRequest.getRequestURI();

        System.out.println(requestURI);
        boolean result = false;
        if (requestURI.endsWith("authenticate")) {
            result = checksForAuthenticateEndpoint(httpServletRequest);
        }

        if (requestURI.endsWith("token")) {
            result = checksForTokenEndpoint(httpServletRequest);
        }


        if (!result) {
            showErrorMessage((HttpServletResponse) response);
        } else {

            // Here we do the default login, including a redirect to login if needed or authenticate from cookie.
            result = super.onPreHandle(request, response, mappedValue);
        }
        return result;
    }

    private boolean checksForTokenEndpoint(HttpServletRequest httpServletRequest) {

        boolean result = true;

        TokenRequest tokenRequest = null;
        try {
            HTTPRequest.Method method = HTTPRequest.Method.valueOf(httpServletRequest.getMethod());
            URL url = new URL(httpServletRequest.getRequestURL().toString());
            HTTPRequest httpRequest = new HTTPRequest(method, url);
            httpRequest.setAuthorization(httpServletRequest.getHeader("Authorization"));
            httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

            String query = httpServletRequest.getReader().readLine();

            System.out.println(query);

            System.out.println(URLUtils.parseParameters(query));
            httpRequest.setQuery(query);

            tokenRequest = TokenRequest.parse(httpRequest);

            ClientAuthentication clientAuthentication = tokenRequest.getClientAuthentication();

            // FIXME Verification of clientAuthentication
            OIDCEndpointToken endpointToken = new OIDCEndpointToken(clientAuthentication);


            SecurityUtils.getSubject().login(endpointToken);

        } catch (MalformedURLException e) {
            result = false;
            e.printStackTrace();
        } catch (ParseException e) {
            result = false;

            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (result) {
            httpServletRequest.setAttribute(AbstractRequest.class.getName(), tokenRequest);

            // Disable the SessionHijacking filter on this request.
            httpServletRequest.setAttribute("sh" + ALREADY_FILTERED_SUFFIX, Boolean.TRUE);
        }
        return result;
    }

    private boolean checksForAuthenticateEndpoint(HttpServletRequest httpServletRequest) {
        String query = httpServletRequest.getQueryString();

        boolean result = true;
        // Decode the query string
        AuthenticationRequest request = null;
        try {
            request = AuthenticationRequest.parse(query);
            // TODO Catch exception?
        } catch (ParseException e) {
            result = false;
            e.printStackTrace();
        }


        String clientId = request.getClientID().getValue();

        /*

        if (responseType != null && responseType.trim().length() > 1) {
            // If response_type is specified, it need to be a valid value.
            // But logout for example doesn't need to parameter.
            SSOFlow ssoFlow = SSOFlow.defineFlow(responseType);
            if (ssoFlow == null) {
                // response_type query parameter is required and needs to be a valid value
                result = false;
            }
        }
        */

        // Check to see if the application is configured
        if (result) {
            ClientInfoRetriever clientInfoRetriever = BeanProvider.getContextualReference(ClientInfoRetriever.class);
            ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(clientId);
            if (clientInfo == null) {
                result = false;
            }
        }

        if (result) {
            ssoHelper.markAsSSOLogin(httpServletRequest, clientId);
            httpServletRequest.setAttribute(AbstractRequest.class.getName(), request);
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
