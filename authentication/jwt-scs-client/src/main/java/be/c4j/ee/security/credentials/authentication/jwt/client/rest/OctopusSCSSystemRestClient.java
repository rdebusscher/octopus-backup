/*
 * Copyright 2014-2018 Rudy De Busscher
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
package be.c4j.ee.security.credentials.authentication.jwt.client.rest;

import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.authentication.octopus.client.ClientCustomization;
import be.c4j.ee.security.credentials.authentication.jwt.client.JWTSystemToken;
import be.c4j.ee.security.jwt.config.MappingSystemAccountToApiKey;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.annotation.PostConstruct;
import javax.enterprise.context.Dependent;
import javax.inject.Inject;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Configuration;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static be.c4j.ee.security.OctopusConstants.*;

/**
 *
 */
@Dependent  // As we can set the systemAccount differently
@PublicAPI
public class OctopusSCSSystemRestClient extends AbstractRestClient {

    @Inject
    private JWTSystemToken jwtSystemToken;

    @Inject
    private MappingSystemAccountToApiKey mappingSystemAccountToApiKey;

    private String systemAccount;

    @PostConstruct
    public void init() {
        ClientCustomization clientCustomization = BeanProvider.getContextualReference(ClientCustomization.class, true);
        Configuration configuration = getConfiguration(clientCustomization);
        if (configuration == null) {

            client = ClientBuilder.newClient();
        } else {
            client = ClientBuilder.newClient(clientCustomization.getConfiguration(this.getClass()));

        }
        if (clientCustomization != null) {
            clientCustomization.customize(client, this.getClass());
        }

        if (mappingSystemAccountToApiKey.containsOnlyOneMapping()) {
            systemAccount = mappingSystemAccountToApiKey.getOnlyAccount();
        }

    }

    private Configuration getConfiguration(ClientCustomization clientCustomization) {
        Configuration result = null;
        if (clientCustomization != null) {
            result = clientCustomization.getConfiguration(this.getClass());
        }
        return result;
    }

    public Client getClient() {
        return client;
    }

    public void addAuthenticationHeader(Invocation.Builder builder) {
        builder.header(AUTHORIZATION_HEADER, getAuthenticationHeader());
        builder.header(X_API_KEY, mappingSystemAccountToApiKey.getApiKey(systemAccount));
    }

    private String getAuthenticationHeader() {
        return BEARER + " " + jwtSystemToken.createJWTSystemToken(systemAccount);
    }

    public <T> T get(String url, Class<T> classType, URLArgument... urlArguments) {
        Invocation.Builder builder = createRequestBuilder(url, urlArguments);

        addAuthenticationHeader(builder);
        Response response = builder
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get();

        handleErrorReturns(url, response, HttpMethod.GET);
        return response.readEntity(classType);
    }

    public <T> T post(String url, Object postBody, Class<T> classType, URLArgument... urlArguments) {
        Invocation.Builder builder = createRequestBuilder(url, urlArguments);

        addAuthenticationHeader(builder);

        Response response = builder
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .post(Entity.entity(postBody, MediaType.APPLICATION_JSON_TYPE));

        handleErrorReturns(url, response, HttpMethod.POST);
        return response.readEntity(classType);
    }

    public <T> T put(String url, Object putBody, Class<T> classType, URLArgument... urlArguments) {
        Invocation.Builder builder = createRequestBuilder(url, urlArguments);
        addAuthenticationHeader(builder);

        Response response = builder
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .put(Entity.entity(putBody, MediaType.APPLICATION_JSON_TYPE));

        handleErrorReturns(url, response, HttpMethod.PUT);
        return response.readEntity(classType);
    }

    public boolean delete(String url, URLArgument... urlArguments) {
        Invocation.Builder builder = createRequestBuilder(url, urlArguments);
        addAuthenticationHeader(builder);

        Response response = builder
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .delete();

        handleErrorReturns(url, response, HttpMethod.DELETE);
        return true; // TODO, should we return void

    }

    public void setSystemAccount(String systemAccount) {
        this.systemAccount = systemAccount;
    }
}
