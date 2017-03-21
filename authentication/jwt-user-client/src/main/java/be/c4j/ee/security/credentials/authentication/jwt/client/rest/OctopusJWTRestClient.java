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
package be.c4j.ee.security.credentials.authentication.jwt.client.rest;


import be.c4j.ee.security.credentials.authentication.jwt.client.JWTClaimsProvider;
import be.c4j.ee.security.credentials.authentication.jwt.client.JWTUserToken;
import be.c4j.ee.security.credentials.authentication.jwt.client.config.JWTClientConfig;
import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import be.c4j.ee.security.filter.ErrorInfo;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 *
 */
@ApplicationScoped
public class OctopusJWTRestClient {


    @Inject
    private JWTUserToken jwtUserToken;

    @Inject
    private JWTClientConfig jwtClientConfig;

    private Client client;

    @PostConstruct
    public void init() {
        client = ClientBuilder.newClient();
    }

    public Client getClient() {
        return client;
    }

    public void addAuthenticationHeader(Invocation.Builder builder, String apiKey, JWTClaimsProvider jwtClaimsProvider) {
        builder.header("Authorization", getAuthenticationHeader(apiKey, jwtClaimsProvider));
        builder.header("x-api-key", apiKey);
    }

    private String getAuthenticationHeader(String apiKey, JWTClaimsProvider jwtClaimsProvider) {
        return "Bearer " + jwtUserToken.createJWTUserToken(apiKey, jwtClaimsProvider);
    }

    public <T> T get(String url, Class<T> classType, URLArgument... urlArguments) {
        return get(url, classType, null, null, urlArguments);
    }

    public <T> T get(String url, Class<T> classType, String apiKey, URLArgument... urlArguments) {
        return get(url, classType, null, apiKey, urlArguments);
    }

    public <T> T get(String url, Class<T> classType, JWTClaimsProvider jwtClaimsProvider, String apiKey, URLArgument... urlArguments) {
        Invocation.Builder builder = client.target(url).request();

        addAuthenticationHeader(builder, apiKey, jwtClaimsProvider);
        Response response = builder
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get();
        // FIXME Status 404 -> Wrong URL
        if (response.getStatus() == 401) {
            ErrorInfo errorInfo = response.readEntity(ErrorInfo.class);
            // TODO put something meaning full in the exception point like URL?
            throw new OctopusUnauthorizedException(errorInfo.getMessage(), null);
        }
        return response.readEntity(classType);
    }

    public <T> T post(String url, Object postBody, Class<T> classType, URLArgument... urlArguments) {
        return post(url, postBody, classType, null, null, urlArguments);
    }

    public <T> T post(String url, Object postBody, Class<T> classType, String apiKey, URLArgument... urlArguments) {
        return post(url, postBody, classType, null, apiKey, urlArguments);
    }

    public <T> T post(String url, Object postBody, Class<T> classType, JWTClaimsProvider jwtClaimsProvider, String apiKey, URLArgument... urlArguments) {
        Invocation.Builder builder = client.target(url).request();
        addAuthenticationHeader(builder, apiKey, jwtClaimsProvider);

        Response response = builder
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .post(Entity.entity(postBody, MediaType.APPLICATION_JSON_TYPE));

        if (response.getStatus() == 401) {
            ErrorInfo errorInfo = response.readEntity(ErrorInfo.class);
            // TODO put something meaning full in the exception point like URL?
            throw new OctopusUnauthorizedException(errorInfo.getMessage(), null);
        }
        return response.readEntity(classType);
    }

    public <T> T put(String url, Object putBody, Class<T> classType, URLArgument... urlArguments) {
        return put(url, putBody, classType, null, null, urlArguments);
    }

    public <T> T put(String url, Object putBody, Class<T> classType, String apiKey, URLArgument... urlArguments) {
        return put(url, putBody, classType, null, apiKey, urlArguments);
    }

    public <T> T put(String url, Object putBody, Class<T> classType, JWTClaimsProvider jwtClaimsProvider, String apiKey, URLArgument... urlArguments) {
        Invocation.Builder builder = client.target(url).request();
        addAuthenticationHeader(builder, apiKey, jwtClaimsProvider);

        Response response = builder
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .put(Entity.entity(putBody, MediaType.APPLICATION_JSON_TYPE));

        if (response.getStatus() == 401) {
            ErrorInfo errorInfo = response.readEntity(ErrorInfo.class);
            // TODO put something meaning full in the exception point like URL?
            throw new OctopusUnauthorizedException(errorInfo.getMessage(), null);
        }
        return response.readEntity(classType);
    }

    public boolean delete(String url, URLArgument... urlArguments) {
        return delete(url, null, null, urlArguments);
    }

    public boolean delete(String url, String apiKey, URLArgument... urlArguments) {
        return delete(url, null, apiKey, urlArguments);
    }

    public boolean delete(String url, JWTClaimsProvider jwtClaimsProvider, String apiKey, URLArgument... urlArguments) {
        Invocation.Builder builder = client.target(url).request();
        addAuthenticationHeader(builder, apiKey, jwtClaimsProvider);

        Response response = builder
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .delete();

        if (response.getStatus() == 401) {
            ErrorInfo errorInfo = response.readEntity(ErrorInfo.class);
            // TODO put something meaning full in the exception point like URL?
            throw new OctopusUnauthorizedException(errorInfo.getMessage(), null);
        }
        return true;

    }

}
