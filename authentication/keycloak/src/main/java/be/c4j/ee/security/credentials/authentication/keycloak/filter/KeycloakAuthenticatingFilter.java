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
 *
 */
package be.c4j.ee.security.credentials.authentication.keycloak.filter;

import be.c4j.ee.security.credentials.authentication.keycloak.KeycloakUser;
import be.c4j.ee.security.credentials.authentication.keycloak.config.KeycloakConfiguration;
import be.c4j.ee.security.token.IncorrectDataToken;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.CredentialsException;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.representations.IDToken;
import org.keycloak.util.JsonSerialization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

/**
 *
 */
public class KeycloakAuthenticatingFilter extends BasicHttpAuthenticationFilter implements Initializable {
    protected final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

    private KeycloakDeployment deployment;

    @Override
    public void init() throws ShiroException {
        KeycloakConfiguration configuration = BeanProvider.getContextualReference(KeycloakConfiguration.class);
        deployment = configuration.getKeycloakDeployment();
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        // TODO See also be.c4j.ee.security.credentials.authentication.oauth2.filter.AbstractOAuth2AuthcFilter
        String authorizationHeader = getAuthzHeader(request);
        if (authorizationHeader == null || authorizationHeader.length() == 0) {
            // TODO This needs to be made uniform between aal filters.
            return new IncorrectDataToken("Authorization header required");
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Attempting to execute login with headers [" + authorizationHeader + "]");
        }

        String[] parts = authorizationHeader.split(" ");
        if (parts.length != 2) {
            return new IncorrectDataToken("Authorization header value incorrect");
        }
        if (!"Bearer".equals(parts[0])) {
            return new IncorrectDataToken("Authorization header value must start with Bearer");
        }

        String url = deployment.getAccountUrl().replace("account", "protocol/openid-connect/userinfo");
        // localhost:8080/auth/realms/demo/protocol/openid-connect/userinfo

        HttpGet get = new HttpGet(url);

        // add request header
        get.addHeader("Authorization", authorizationHeader);
        get.addHeader("Accept", "application/json");

        KeycloakUser result = null;
        try {
            HttpResponse userInfoResponse = deployment.getClient().execute(get);
            if (userInfoResponse.getStatusLine().getStatusCode() == 200) {
                String id = EntityUtils.toString(userInfoResponse.getEntity());

                IDToken idToken = JsonSerialization.readValue(id, IDToken.class);
                result = KeycloakUser.fromIdToken(idToken);
                if (idToken.getId() == null) {
                    result.setId(parts[1]); // TODO Why is the id not filled in?
                }


            } else {
                throw new CredentialsException(userInfoResponse.getStatusLine().getReasonPhrase());
            }
        } catch (IOException e) {
            throw new CredentialsException(e.getMessage());
        }

        return result;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return executeLogin(request, response);
    }

/*
    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request, ServletResponse response) {
        if (e != null) {
            throw e; // Propagate the error further so that UserRest filter can properly handle it.
        }
        return super.onLoginFailure(token, e, request, response);
    }
    */
}
