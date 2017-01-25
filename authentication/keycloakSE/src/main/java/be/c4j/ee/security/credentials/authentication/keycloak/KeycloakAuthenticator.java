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
package be.c4j.ee.security.credentials.authentication.keycloak;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.OIDCAuthenticationError;
import org.keycloak.adapters.ServerRequest;
import org.keycloak.adapters.authentication.ClientCredentialsProviderUtils;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * TODO Use the refresh token to get a new set of tokens.
 * http://connect2id.com/learn/openid-connect
 */
public class KeycloakAuthenticator {

    protected KeycloakDeployment deployment;

    public KeycloakAuthenticator(String path) {
        InputStream is = this.getClass().getResourceAsStream(path);
        if (is == null) {
            try {
                is = new FileInputStream(path);
            } catch (FileNotFoundException e) {
                ;
                //Will be handled by the check is == null
            }
        }

        if (is == null) {
            throw new OctopusConfigurationException("unable to load keycloak deployment configuration from " + path);
        }
        deployment = KeycloakDeploymentBuilder.build(is);

    }

    public KeycloakAuthenticator(KeycloakDeployment deployment) {
        this.deployment = deployment;
    }

    public KeycloakUser authenticate(String username, String password) throws Exception {
        AccessTokenResponse accessToken = getAccessToken(username, password);

        AccessTokenHandler handler = new AccessTokenHandler(deployment, accessToken);
        return handler.extractUser();
    }

    public void validate(String token) {
        try {
            List<NameValuePair> formparams = new ArrayList<NameValuePair>();

            formparams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, "refresh_token"));
            formparams.add(new BasicNameValuePair(OAuth2Constants.REFRESH_TOKEN, token));
            //formparams.add(new BasicNameValuePair(OAuth2Constants.REDIRECT_URI, "http://localhost"));

            HttpPost post = new HttpPost(deployment.getTokenUrl());
            ClientCredentialsProviderUtils.setClientCredentials(deployment, post, formparams);

            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
            post.setEntity(form);
            HttpResponse response = deployment.getClient().execute(post);
            int status = response.getStatusLine().getStatusCode();

            if (status != 200) {
                throw new OIDCAuthenticationException(OIDCAuthenticationError.Reason.INVALID_TOKEN);
            }
            // TODO Refresh the tokens
        } catch (IOException e) {
            throw new OIDCAuthenticationException(OIDCAuthenticationError.Reason.OAUTH_ERROR);
        }
    }

    private AccessTokenResponse getAccessToken(String username, String password) throws Exception {
        AccessTokenResponse tokenResponse = null;
        HttpClient client = deployment.getClient();

        HttpPost post = new HttpPost(
                KeycloakUriBuilder.fromUri(deployment.getAuthServerBaseUrl())
                        .path(ServiceUrlConstants.TOKEN_PATH).build(deployment.getRealm()));
        List<NameValuePair> formparams = new ArrayList<NameValuePair>();
        formparams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD));
        formparams.add(new BasicNameValuePair("username", username));
        formparams.add(new BasicNameValuePair("password", password));

        ClientCredentialsProviderUtils.setClientCredentials(deployment, post, formparams);

        UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
        post.setEntity(form);

        HttpResponse response = client.execute(post);
        int status = response.getStatusLine().getStatusCode();
        HttpEntity entity = response.getEntity();
        if (status != 200) {
            EntityUtils.consumeQuietly(entity);
            throw new IOException("Bad status: " + status);
        }
        if (entity == null) {
            throw new IOException("No Entity");
        }
        java.io.InputStream is = entity.getContent();
        try {
            tokenResponse = JsonSerialization.readValue(is, AccessTokenResponse.class);
        } finally {
            try {
                is.close();
            } catch (IOException ignored) {
            }
        }

        return (tokenResponse);
    }

    public void logout(KeycloakUser user) {
        try {
            ServerRequest.invokeLogout(deployment, user.getAccessToken().getRefreshToken());
        } catch (IOException e) {
            e.printStackTrace(); // FIXME
        } catch (ServerRequest.HttpFailure httpFailure) {
            httpFailure.printStackTrace();  // FIXME
        }
    }

}
