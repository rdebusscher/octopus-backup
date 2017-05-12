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
package be.c4j.ee.security.credentials.authentication.jwt.filter;

import be.c4j.ee.security.credentials.authentication.jwt.jwt.JWKManager;
import be.c4j.ee.security.credentials.authentication.jwt.jwt.JWTHelper;
import be.c4j.ee.security.token.IncorrectDataToken;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import static be.c4j.ee.security.OctopusConstants.*;

/**
 *
 */
public class JWTAuthenticatingFilter extends AuthenticatingFilter implements Initializable {

    private JWKManager jwkManager;

    private JWTHelper jwtHelper;

    @Override
    public void init() throws ShiroException {
        jwkManager = BeanProvider.getContextualReference(JWKManager.class);
        jwtHelper = BeanProvider.getContextualReference(JWTHelper.class);
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String apiKey = httpServletRequest.getHeader(X_API_KEY);
        String token = httpServletRequest.getHeader(AUTHORIZATION_HEADER);

        return createJWTUser(httpServletRequest, apiKey, token);
    }

    private AuthenticationToken createJWTUser(HttpServletRequest request, String apiKey, String token) {
        if (apiKey == null) {
            // x-api-key header parameter is required.
            return new IncorrectDataToken("x-api-key header required");
        }
        if (!jwkManager.existsApiKey(apiKey)) {
            // x-api-key isn't know in the JWK file
            return new IncorrectDataToken("x-api-key header value unknown : " + apiKey);
        }
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

        return jwtHelper.createOctopusToken(request, apiKey, parts[1]);
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
        return super.onLoginFailure(token, e, request, response);
    }
}
