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

import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.shiro.OctopusUserFilter;
import be.c4j.ee.security.sso.server.client.ClientInfo;
import be.c4j.ee.security.sso.server.client.ClientInfoRetriever;
import be.c4j.ee.security.sso.server.cookie.SSOHelper;
import be.c4j.ee.security.sso.server.token.OIDCEndpointToken;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.commons.lang3.StringUtils;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.ShiroException;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authc.UserFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Map;

/**
 * Filter for the Authenticate and token endpoint.
 */
public class OIDCEndpointFilter extends UserFilter implements Initializable {

    private static final Logger LOGGER = LoggerFactory.getLogger(OIDCEndpointFilter.class);

    private OctopusUserFilter octopusUserFilter;

    @Inject
    private SSOHelper ssoHelper;

    @Inject
    private ClientInfoRetriever clientInfoRetriever;

    @Override
    public void init() throws ShiroException {
        BeanProvider.injectFields(this);
    }

    @Override
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {

        HttpServletRequest httpServletRequest = (HttpServletRequest) request;

        String requestURI = httpServletRequest.getRequestURI();

        ErrorInfo errorInfo = null;
        EndpointType endpointType = null;
        if (requestURI.endsWith("authenticate")) {
            errorInfo = checksForAuthenticateEndpoint(httpServletRequest);
            endpointType = EndpointType.AUTHENTICATE;
        }

        if (requestURI.endsWith("token")) {
            errorInfo = checksForTokenEndpoint(httpServletRequest);
            endpointType = EndpointType.TOKEN;
        }

        boolean result;
        if (errorInfo != null) {
            showErrorMessage((HttpServletResponse) response, endpointType, errorInfo);
            result = false;
        } else {

            // Here we do the default login, including a redirect to login if needed or authenticate from cookie.
            result = super.onPreHandle(request, response, mappedValue);
        }
        return result;
    }

    private void showErrorMessage(HttpServletResponse response, EndpointType endpointType, ErrorInfo errorInfo) {


        switch (endpointType) {

            case AUTHENTICATE:
                if (errorInfo.getRedirectURI() == null) {
                    // We don't have a valid redirectURI, so we can only replay in the current response.
                    try {
                        response.getWriter().println(errorInfo.getErrorObject().getDescription());
                    } catch (IOException e) {
                        throw new OctopusUnexpectedException(e);
                    }
                } else {
                    AuthenticationErrorResponse errorResponse = new AuthenticationErrorResponse(errorInfo.getRedirectURI(), errorInfo.getErrorObject(), errorInfo.getState(), ResponseMode.QUERY);

                    try {
                        response.sendRedirect(errorResponse.toHTTPResponse().getLocation().toString());
                    } catch (IOException e) {
                        throw new OctopusUnexpectedException(e);
                    }
                }
                break;
            case TOKEN:
                TokenErrorResponse tokenErrorResponse = new TokenErrorResponse(errorInfo.getErrorObject());
                System.out.println(tokenErrorResponse.toJSONObject()); // FIXME
                break;
            default:
                throw new IllegalArgumentException(String.format("EndpointType %s not supported", endpointType));
        }

    }

    private ErrorInfo checksForTokenEndpoint(HttpServletRequest httpServletRequest) {

        boolean result = true;

        TokenRequest tokenRequest = null;
        try {
            HTTPRequest.Method method = HTTPRequest.Method.valueOf(httpServletRequest.getMethod());
            URL url = new URL(httpServletRequest.getRequestURL().toString());
            HTTPRequest httpRequest = new HTTPRequest(method, url);
            httpRequest.setAuthorization(httpServletRequest.getHeader("Authorization"));
            httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

            String query = httpServletRequest.getReader().readLine();

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
        return null;
    }

    private ErrorInfo checksForAuthenticateEndpoint(HttpServletRequest httpServletRequest) {
        String query = httpServletRequest.getQueryString();

        // Decode the query string
        AuthenticationRequest request;
        try {
            request = AuthenticationRequest.parse(query);
        } catch (ParseException e) {
            LOGGER.info(e.getMessage());
            Map<String, String> queryParameters = URLUtils.parseParameters(query);
            return new ErrorInfo(queryParameters, e.getErrorObject());
        }


        String clientId = request.getClientID().getValue();

        // Check to see if the application is configured
        ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(clientId);
        if (clientInfo == null) {
            String msg = "Unknown \"client_id\" parameter value";
            LOGGER.info(msg + " = " + clientId);
            return new ErrorInfo(request, OAuth2Error.INVALID_CLIENT.appendDescription(": " + msg));
        }


        if (!request.getRedirectionURI().toString().equals(clientInfo.getActualCallbackURL())) {
            String msg = "Unknown \"redirect_uri\" parameter value";
            LOGGER.info(msg + " = " + clientId);
            return new ErrorInfo(request, OAuth2Error.INVALID_CLIENT.appendDescription(": " + msg));
        }


        ssoHelper.markAsSSOLogin(httpServletRequest, clientId);
        httpServletRequest.setAttribute(AbstractRequest.class.getName(), request);

        return null;
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

    enum EndpointType {
        AUTHENTICATE, TOKEN
    }

    private class ErrorInfo {

        private URI redirectURI;
        private State state;
        private ErrorObject errorObject;

        public ErrorInfo(Map<String, String> queryParameters, ErrorObject errorObject) {
            state = State.parse(queryParameters.get("state"));
            redirectURI = getRedirectURI(queryParameters);
            this.errorObject = errorObject;
        }

        public ErrorInfo(AuthenticationRequest request, ErrorObject errorObject) {
            state = request.getState();
            redirectURI = request.getRedirectionURI();
            this.errorObject = errorObject;
        }

        private URI getRedirectURI(Map<String, String> queryParameters) {
            String paramValue = queryParameters.get("redirect_uri");

            URI result = null;

            if (StringUtils.isNotBlank(paramValue)) {

                try {
                    result = new URI(paramValue);

                } catch (URISyntaxException e) {
                    // It is possible that the RP send an invalid redirectURI
                }
            }

            return result;

        }

        public URI getRedirectURI() {
            return redirectURI;
        }

        public State getState() {
            return state;
        }

        public ErrorObject getErrorObject() {
            return errorObject;
        }
    }
}
