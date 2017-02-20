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
package be.c4j.ee.security.credentials.authentication.jwt.client;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;

/**
 *
 */
@ApplicationScoped
public class OctopusJWTRestClient {


    @Inject
    private JWTUserToken jwtUserToken;

    private Client client;

    @PostConstruct
    public void init() {
        client = ClientBuilder.newClient();
    }

    public <T> T get(String url, MediaType mediaType, Class<T> classType) {
        // FIXME Use URL pattern like trello API
        return client.target(url).request(mediaType).header("Authorization", "Bearer " + jwtUserToken.createJWTUserToken())
                .get().readEntity(classType);
    }

    public <T> T post(String url, Object postBody, MediaType mediaType, Class<T> classType) {
        // FIXME Specify mediatype for Post
        return client.target(url).request(mediaType).header("Authorization", "Bearer " + jwtUserToken.createJWTUserToken())
                .post(Entity.entity(postBody, MediaType.APPLICATION_JSON_TYPE)).readEntity(classType);
    }

    public <T> T put(String url, Object putBody, MediaType mediaType, Class<T> classType) {
        // FIXME Specify mediatype for Put ?
        return client.target(url).request(mediaType).header("Authorization", "Bearer " + jwtUserToken.createJWTUserToken())
                .put(Entity.entity(putBody, MediaType.APPLICATION_JSON_TYPE)).readEntity(classType);
    }

    public boolean delete(String url) {

        return client.target(url).request().header("Authorization", "Bearer " + jwtUserToken.createJWTUserToken())
                .delete().getStatus() == 200;
    }

}
