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
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.server.endpoint.AccessTokenTransformer;
import be.c4j.ee.security.sso.server.store.OIDCStoreData;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import be.c4j.ee.security.token.IncorrectDataToken;
import com.nimbusds.oauth2.sdk.Scope;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static be.c4j.ee.security.OctopusConstants.*;

/**
 * TODO User endpoint must use https. Config parameter to disable this check (as sometime OIDC based server used purely internally.)
 * But when disabled, put a warning message in the log.
 */
public class SSOAuthenticatingFilter extends AuthenticatingFilter implements Initializable {

    private Logger logger = LoggerFactory.getLogger(SSOAuthenticatingFilter.class);

    @Inject
    private SSOTokenStore tokenStore;

    @Inject
    private OctopusConfig octopusConfig;

    private AccessTokenTransformer accessTokenTransformer;

    @Override
    public void init() throws ShiroException {
        BeanProvider.injectFields(this);
        accessTokenTransformer = BeanProvider.getContextualReference(AccessTokenTransformer.class, true);
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String apiKey = httpServletRequest.getHeader(X_API_KEY);
        String token = httpServletRequest.getHeader(AUTHORIZATION_HEADER);

        return createSSOUser(httpServletRequest, apiKey, token);
    }

    private AuthenticationToken createSSOUser(ServletRequest request, String apiKey, String token) {

        if (token == null) {
            // Authorization header parameter is required.
            return new IncorrectDataToken("Authorization header required");
        }

        String[] parts = token.split(" ");
        if (parts.length != 2) {
            return new IncorrectDataToken("Authorization header value incorrect");
        }
        if (!BEARER.equals(parts[0])) {
            return new IncorrectDataToken("Authorization header value must start with Bearer");
        }

        OctopusSSOUser octopusToken = createOctopusToken(request, apiKey, parts[1]);
        if (octopusToken == null) {
            return new IncorrectDataToken("Authentication failed");
        }
        return octopusToken;
    }

    private OctopusSSOUser createOctopusToken(ServletRequest request, String apiKey, String token) {
        String accessToken = null;

        String realToken;
        // Special custom requirements to the accessToken like signed tokens
        if (accessTokenTransformer != null) {
            realToken = accessTokenTransformer.transformAccessToken(token);
        } else {
            realToken = token;
        }

        OctopusSSOUser user = tokenStore.getUserByAccessCode(realToken);

        if (user != null) {
            // We have found a User for the token.
            accessToken = realToken;
        }

        if (user == null) {
            logger.info("No user information found for token " + token);
        } else {
            // Put the scope on the request so that the endpoint can use this information
            OIDCStoreData oidcStoreData = tokenStore.getOIDCDataByAccessToken(accessToken);
            request.setAttribute(Scope.class.getName(), oidcStoreData.getScope());

            showDebugInfo(user);
        }
        return user;
    }

    private void showDebugInfo(OctopusSSOUser user) {
        if (octopusConfig == null) {
            octopusConfig = BeanProvider.getContextualReference(OctopusConfig.class);
            logger = LoggerFactory.getLogger(SSOAuthenticatingFilter.class);
        }

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("(SSO Server) User %s is authenticated from Authorization Header (cookie token = %s)", user.getFullName(), user.getCookieToken()));
        }
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return executeLogin(request, response);
    }

    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request, ServletResponse response) {
        if (e != null) {
            throw e; // Propagate the error further so that UserRest filter can properly handle it.
        }
        return super.onLoginFailure(token, null, request, response);
    }

    /**
     * Overrides the default behavior to show and swallow the exception if the exception is
     * {@link org.apache.shiro.authz.UnauthenticatedException}.
     */
    @Override
    protected void cleanup(ServletRequest request, ServletResponse response, Exception existing) throws ServletException, IOException {
        Exception exception = existing;
        Throwable unauthorized = OctopusUnauthorizedException.getUnauthorizedException(exception);
        if (unauthorized != null) {
            try {
                ((HttpServletResponse) response).setStatus(401);
                response.getOutputStream().println(unauthorized.getMessage());
                exception = null;
            } catch (Exception e) {
                exception = e;
            }
        }
        super.cleanup(request, response, exception);

    }
}
