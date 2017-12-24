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
package be.c4j.ee.security.credentials.authentication.keycloak.servlet;

import be.c4j.ee.security.authentication.ActiveSessionRegistry;
import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.credentials.authentication.keycloak.AccessTokenHandler;
import be.c4j.ee.security.credentials.authentication.keycloak.KeycloakUser;
import be.c4j.ee.security.credentials.authentication.keycloak.OIDCAuthenticationException;
import be.c4j.ee.security.credentials.authentication.keycloak.config.KeycloakConfiguration;
import be.c4j.ee.security.session.SessionUtil;
import be.c4j.ee.security.util.URLUtil;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OIDCAuthenticationError;
import org.keycloak.adapters.ServerRequest;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.enums.TokenStore;
import org.keycloak.representations.AccessTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 *
 */
public class OIDCAdapter {

    private Logger logger;

    private KeycloakDeployment deployment;

    private HttpServletRequest request;

    private HttpServletResponse response;

    private OctopusJSFConfig octopusConfig;
    private KeycloakConfiguration keycloakConfiguration;
    private SessionUtil sessionUtil;
    private URLUtil urlUtil;

    private ActiveSessionRegistry activeSessionRegistry;

    public OIDCAdapter(KeycloakDeployment deployment, HttpServletRequest request, HttpServletResponse response, OctopusJSFConfig octopusConfig, KeycloakConfiguration keycloakConfiguration, ActiveSessionRegistry activeSessionRegistry, SessionUtil sessionUtil, URLUtil urlUtil) {
        this.deployment = deployment;
        this.request = request;
        this.response = response;
        this.octopusConfig = octopusConfig;
        this.keycloakConfiguration = keycloakConfiguration;
        this.sessionUtil = sessionUtil;
        this.urlUtil = urlUtil;
        logger = LoggerFactory.getLogger(OIDCAdapter.class);

        this.activeSessionRegistry = activeSessionRegistry;
    }

    public String getCode() {
        return getQueryParamValue(OAuth2Constants.CODE);
    }

    public String getState() {
        return getQueryParamValue(OAuth2Constants.STATE);
    }

    private String getQueryParamValue(String paramName) {
        return request.getParameter(paramName);
    }

    protected String getRedirectUri(String state) {
        String url = urlUtil.determineRoot(request) + "/keycloak";
        // log.debugf("callback uri: %s", url);
        /*
        if (!facade.getRequest().isSecure() && deployment.getSslRequired().isRequired(facade.getRequest().getRemoteAddr())) {
            int port = sslRedirectPort();
            if (port < 0) {
                // disabled?
                return null;
            }
            KeycloakUriBuilder secureUrl = KeycloakUriBuilder.fromUri(url).scheme("https").port(-1);
            if (port != 443) {
                secureUrl.port(port);
            }
            url = secureUrl.build().toString();
        }
        */

        /*
        String idpHint = getQueryParamValue(AdapterConstants.KC_IDP_HINT);
        url = UriUtils.stripQueryParam(url, AdapterConstants.KC_IDP_HINT);

        String scope = getQueryParamValue(OAuth2Constants.SCOPE);
        url = UriUtils.stripQueryParam(url, OAuth2Constants.SCOPE);

        String prompt = getQueryParamValue(OAuth2Constants.PROMPT);
        url = UriUtils.stripQueryParam(url, OAuth2Constants.PROMPT);

        String maxAge = getQueryParamValue(OAuth2Constants.MAX_AGE);
        url = UriUtils.stripQueryParam(url, OAuth2Constants.MAX_AGE);
*/
        KeycloakUriBuilder redirectUriBuilder = deployment.getAuthUrl().clone()
                .queryParam(OAuth2Constants.RESPONSE_TYPE, OAuth2Constants.CODE)
                .queryParam(OAuth2Constants.CLIENT_ID, deployment.getResourceName())
                .queryParam(OAuth2Constants.REDIRECT_URI, url)
                .queryParam(OAuth2Constants.STATE, state)
                .queryParam("login", "true");

        /*
        TODO Support this; prefill the username field of login form
        if (loginHint != null && loginHint.length() > 0) {
            redirectUriBuilder.queryParam("login_hint", loginHint);
        }
        */

        String idpHint = keycloakConfiguration.getIdpHint();
        if (idpHint != null && idpHint.length() > 0) {
            redirectUriBuilder.queryParam(AdapterConstants.KC_IDP_HINT, idpHint);
        }


        /*
        if (prompt != null && prompt.length() > 0) {
            redirectUriBuilder.queryParam(OAuth2Constants.PROMPT, prompt);
        }
        if (maxAge != null && maxAge.length() > 0) {
            redirectUriBuilder.queryParam(OAuth2Constants.MAX_AGE, maxAge);
        }
        */

        String scope = keycloakConfiguration.getScopes();
        scope = attachOIDCScope(scope);
        redirectUriBuilder.queryParam(OAuth2Constants.SCOPE, scope);

        return redirectUriBuilder.build().toString();
    }

    private String attachOIDCScope(String scopeParam) {
        return scopeParam != null && !scopeParam.isEmpty() ? "openid " + scopeParam : "openid";
    }

    public void authenticate(String code) throws IOException {
        // abort if not HTTPS
        /*
        if (!isRequestSecure() && deployment.getSslRequired().isRequired(facade.getRequest().getRemoteAddr())) {
            log.error("Adapter requires SSL. Request: " + facade.getRequest().getURI());
            return challenge(403, OIDCAuthenticationError.Reason.SSL_REQUIRED, null);
        }
        */

        checkCsrfToken();

        AccessTokenResponse tokenResponse = retrieveToken(code);
        if (tokenResponse == null) {
            // If call failed to, error already send so sto processing
            return;
        }

        AccessTokenHandler handler = new AccessTokenHandler(deployment, tokenResponse);
        KeycloakUser user;
        try {
            user = handler.extractUser();
        } catch (OIDCAuthenticationException ex) {
            sendError(response, ex.getReason());
            return;

        }

        try {

            sessionUtil.invalidateCurrentSession(request);

            SecurityUtils.getSubject().login(user);

            activeSessionRegistry.startSession(user.getClientSession(), SecurityUtils.getSubject().getPrincipal());

            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(request);
            response.sendRedirect(savedRequest != null ? savedRequest.getRequestUrl() : request.getContextPath());
        } catch (AuthenticationException e) {
            HttpSession sess = request.getSession();
            //sess.setAttribute(OAuth2User.OAUTH2_USER_INFO, oAuth2User); TODO
            sess.setAttribute("AuthenticationExceptionMessage", e.getMessage());
            // DataSecurityProvider decided that  user has no access to application
            response.sendRedirect(request.getContextPath() + octopusConfig.getUnauthorizedExceptionPage());
        }

        logger.debug("successful authenticated");

    }

    private AccessTokenResponse retrieveToken(String code) throws IOException {
        AccessTokenResponse result = null;
        String strippedOauthParametersRequestUri = stripOauthParametersFromRedirect(request);
        try {
            // For COOKIE store we don't have httpSessionId and single sign-out won't be available
            String httpSessionId = deployment.getTokenStore() == TokenStore.SESSION ? request.getSession().getId() : null;
            result = ServerRequest.invokeAccessCodeToToken(deployment, code, strippedOauthParametersRequestUri, httpSessionId);
        } catch (ServerRequest.HttpFailure failure) {
            logger.error("failed to turn code into token");
            logger.error("status from server: " + failure.getStatus());
            if (failure.getStatus() == 400 && failure.getError() != null) {
                logger.error("   " + failure.getError());
            }
            sendError(response, OIDCAuthenticationError.Reason.CODE_TO_TOKEN_FAILURE);

        } catch (IOException e) {
            logger.error("failed to turn code into token", e);
            sendError(response, OIDCAuthenticationError.Reason.CODE_TO_TOKEN_FAILURE);
        }
        return result;

    }

    private void checkCsrfToken() throws IOException {
        logger.debug("checking state cookie for after code");
        if (!checkStateCookie()) {
            logger.warn("The CSRF token does not match");
            // The CSRF token do not match, deny access.
            HttpSession sess = request.getSession();
            sess.invalidate();
            response.sendRedirect(request.getContextPath());
        }
    }

    private void sendError(HttpServletResponse response, OIDCAuthenticationError.Reason errorCode) throws IOException {
        response.sendError(HttpServletResponse.SC_FORBIDDEN, errorCode.name());
    }

    /**
     * strip out unwanted query parameters and redirect so bookmarks don't retain oauth protocol bits
     */
    protected String stripOauthParametersFromRedirect(HttpServletRequest request) {
        String url = request.getRequestURL().toString();
        KeycloakUriBuilder builder = KeycloakUriBuilder.fromUri(url)
                .replaceQueryParam(OAuth2Constants.CODE, null)
                .replaceQueryParam(OAuth2Constants.STATE, null);
        return builder.build().toString();
    }

    public boolean checkStateCookie() {
        return request.getSession().getAttribute(OAuth2Constants.STATE).equals(getState());
    }
}
