/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.sso.server.endpoint;

import be.c4j.ee.security.authentication.ActiveSessionRegistry;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import be.c4j.ee.security.sso.rest.AuthenticationInfo;
import be.c4j.ee.security.sso.server.rest.RestAuthenticationHandler;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;

import javax.ejb.Singleton;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 *
 */
@Path("/octopus/rest")
@Singleton
public class OctopusSSORestEndpoint {

    @Inject
    private SSODataEncryptionHandler encryptionHandler;

    @Inject
    private JSONHandler jsonHandler;

    @Inject
    private RestAuthenticationHandler authenticationHandler;

    @Inject
    private PrepareSSORestEndpoint prepareSSORestEndpoint;

    @Inject
    private SSOTokenStore tokenStore;

    @Inject
    private ActiveSessionRegistry activeSessionRegistry;

    // FIXME Add these URLs automatically to the securedURL to that the user doesn't need to add them.

    @Path("/user")
    @POST
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.TEXT_PLAIN)
    public String getUserInfo(String token, @HeaderParam("x-api-key") String apiKey, @Context HttpServletRequest httpServletRequest) {
        prepareSSORestEndpoint.init(httpServletRequest);
        String result = null;
        if (encryptionHandler.validate(apiKey, token)) {
            String data = encryptionHandler.decryptData(token, apiKey);
            AuthenticationInfo authenticationInfo = jsonHandler.decodeFromJSON(data);
            UserPrincipal userPrincipal = authenticationHandler.validate(authenticationInfo);

            if (userPrincipal != null) {
                OctopusSSOUser user = userPrincipal.getUserInfo(OctopusSSOUser.USER_INFO_KEY);
                tokenStore.keepToken(user);

                activeSessionRegistry.startSession(userPrincipal.getId().toString(), userPrincipal);

                result = encryptionHandler.encryptData(user.getToken(), apiKey);
            }
        }
        if (result == null) {
            throw new WebApplicationException(Response.Status.UNAUTHORIZED);
        }
        return result;
    }
}
