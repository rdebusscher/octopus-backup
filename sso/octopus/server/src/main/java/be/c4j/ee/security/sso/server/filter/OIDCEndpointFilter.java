/*
 * Copyright 2014-2018 Rudy De Busscher (www.c4j.be)
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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_HEADER;

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

    @Inject
    private OctopusClientCredentialsSelector selector;

    @Override
    public void init() throws ShiroException {
        BeanProvider.injectFields(this);
    }

    @Override
    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {

        HttpServletRequest httpServletRequest = (HttpServletRequest) request;

        String requestURI = httpServletRequest.getRequestURI();
        if (requestURI.contains(";")) {
            // Strip off any additional info (like jsessionid encoded in URL)
            requestURI = requestURI.substring(0, requestURI.indexOf(';'));
        }

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

        if (endpointType == null) {
            throw new OctopusUnexpectedException("Enpoint URL not recognized by the OIDCEndpointFilter " + requestURI);
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

                    // TODO Check OAuth2 spec 4.1.2.1 We should not always return the error as redirect.
                    try {
                        response.sendRedirect(errorResponse.toHTTPResponse().getLocation().toString());
                    } catch (IOException e) {
                        throw new OctopusUnexpectedException(e);
                    }
                }
                break;
            case TOKEN:
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.setHeader("Content-Type", "application/json");
                TokenErrorResponse tokenErrorResponse = new TokenErrorResponse(errorInfo.getErrorObject());
                try {
                    response.getWriter().println(tokenErrorResponse.toJSONObject().toJSONString());
                } catch (IOException e) {
                    throw new OctopusUnexpectedException(e);
                }
                break;
            default:
                throw new IllegalArgumentException(String.format("EndpointType %s not supported", endpointType));
        }

    }

    private ErrorInfo checksForTokenEndpoint(HttpServletRequest httpServletRequest) {

        ErrorInfo result = null;

        TokenRequest tokenRequest = null;
        try {
            HTTPRequest.Method method = HTTPRequest.Method.valueOf(httpServletRequest.getMethod());
            URL url = new URL(httpServletRequest.getRequestURL().toString());
            HTTPRequest httpRequest = new HTTPRequest(method, url);
            httpRequest.setAuthorization(httpServletRequest.getHeader(AUTHORIZATION_HEADER));
            httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

            String query = httpServletRequest.getReader().readLine();

            httpRequest.setQuery(query);

            tokenRequest = TokenRequest.parse(httpRequest);

            GrantType grantType = tokenRequest.getAuthorizationGrant().getType();
            if (grantType.requiresClientAuthentication() || tokenRequest.getClientAuthentication() != null) {
                result = checkClientCredentials(tokenRequest, url, httpRequest, grantType);
            }

            if (result == null && GrantType.PASSWORD.equals(grantType)) {

                //when scope contains openid or openid/octopus -> clientAuthentication required
                if (hasIdScopes(tokenRequest) && tokenRequest.getClientAuthentication() == null) {
                    ErrorObject errorObject = new ErrorObject("OCT-SSO-SERVER-013", "Scope requires client Authentication");
                    result = new ErrorInfo(errorObject);

                } else {

                    // Well not completely correctly but
                    // If call isn't authenticated at the end of the filter, there is a redirect to the Login page
                    // So we need to do a login, and we have already one for the OIDCEndpointToken
                    // So we reuse this. And username password it basically a clientAuthentication so not too bad.

                    ResourceOwnerPasswordCredentialsGrant passwordGrant = (ResourceOwnerPasswordCredentialsGrant) tokenRequest.getAuthorizationGrant();
                    ClientID username = new ClientID(passwordGrant.getUsername());
                    ClientAuthentication clientAuthentication = new ClientSecretBasic(username, passwordGrant.getPassword());
                    SecurityUtils.getSubject().login(new OIDCEndpointToken(clientAuthentication));
                }
            }

        } catch (MalformedURLException e) {
            // new URL(httpServletRequest.getRequestURL().toString());
            ErrorObject errorObject = new ErrorObject("OCT-SSO-SERVER-100", "invalid URL");
            result = new ErrorInfo(errorObject);

        } catch (ParseException e) {
            // TokenRequest.parse(httpRequest);
            result = new ErrorInfo(e.getErrorObject());
        } catch (IOException e) {
            throw new OctopusUnexpectedException(e);
        }

        if (result == null) {
            httpServletRequest.setAttribute(AbstractRequest.class.getName(), tokenRequest);

            // Disable the SessionHijacking filter on this request.
            httpServletRequest.setAttribute("sh" + ALREADY_FILTERED_SUFFIX, Boolean.TRUE);
        }
        return result;
    }

    private boolean hasIdScopes(TokenRequest tokenRequest) {
        return tokenRequest.getScope() != null
                && (tokenRequest.getScope().contains("openid") || tokenRequest.getScope().contains("octopus"));
    }

    private ErrorInfo checkClientCredentials(TokenRequest tokenRequest, URL url, HTTPRequest httpRequest, GrantType grantType) {
        ErrorInfo result = null;
        ClientAuthentication clientAuthentication = tokenRequest.getClientAuthentication();

        Set<Audience> expectedAudience = new HashSet<Audience>();
        expectedAudience.add(new Audience(url.toExternalForm()));

        ClientAuthenticationVerifier<Object> authenticationVerifier = new ClientAuthenticationVerifier<Object>(selector, expectedAudience);

        try {
            authenticationVerifier.verify(clientAuthentication, null, null);
        } catch (InvalidClientException e) {
            LOGGER.info(e.getMessage());
            result = new ErrorInfo(e.getErrorObject());
        } catch (JOSEException e) {
            ErrorObject errorObject = new ErrorObject("OCT-SSO-SERVER-011", "invalid JWT");
            result = new ErrorInfo(errorObject);
        }

        if (result == null) {
            ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(clientAuthentication.getClientID().getValue());

            // TODO clientInfo should never be null, is already checked by the clientAuthenticationVerifier.
            if (!checkRedirectURI(httpRequest, clientInfo, grantType)) {
                // 3.1.3.2 Ensure that the redirect_uri parameter value is identical to the redirect_uri parameter value that was included in the initial Authorization Request
                result = new ErrorInfo(new ErrorObject("OCT-SSO-SERVER-012", "Invalid \"redirect_uri\" parameter: "));
            } else {

                OIDCEndpointToken endpointToken = new OIDCEndpointToken(clientAuthentication);

                SecurityUtils.getSubject().login(endpointToken);

                // OK, we will check if
                // - Authorization Code is still valid.
                // - Authorization code is issued for the same ClientId
            }
        }
        return result;
    }

    private boolean checkRedirectURI(HTTPRequest httpRequest, ClientInfo clientInfo, GrantType grantType) {
        boolean result = true;
        if (GrantType.AUTHORIZATION_CODE.equals(grantType) || GrantType.IMPLICIT.equals(grantType)) {
            String redirectUri = httpRequest.getQueryParameters().get("redirect_uri");
            result = checkCallbackUrl(clientInfo, redirectUri);
        }
        return result;
    }

    private boolean checkCallbackUrl(ClientInfo clientInfo, String redirectUri) {
        boolean result = clientInfo.getActualCallbackURL().equals(redirectUri);
        if (!result && clientInfo.hasMultipleCallbackURL()) {
            Iterator<String> iterator = clientInfo.getAdditionalCallbackURLs().iterator();
            while (!result && iterator.hasNext()) {
                result = iterator.next().equals(redirectUri);
            }
        }
        return result;
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

        String redirectUri = request.getRedirectionURI().toString();
        boolean result = checkCallbackUrl(clientInfo, redirectUri);

        if (!result) {
            String msg = "Unknown \"redirect_uri\" parameter value";
            LOGGER.info(msg + " = " + request.getRedirectionURI());
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

        public ErrorInfo(ErrorObject errorObject) {
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
