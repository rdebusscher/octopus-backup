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
package be.c4j.ee.security.credentials.authentication.oauth2.info;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2ProviderMetaData;
import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.model.UserPrincipal;
import com.github.scribejava.core.model.Token;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Iterator;
import java.util.List;

/**
 *
 */
@Path("/user")
@Singleton
public class UserController {

    private List<OAuth2ProviderMetaData> oAuth2ProviderMetaDataList;

    @Inject
    private ExternalInternalIdMapper externalInternalIdMapper;

    @Inject
    private UserPrincipal userPrincipal;

    @PostConstruct
    public void init() {
        oAuth2ProviderMetaDataList = BeanProvider.getContextualReferences(OAuth2ProviderMetaData.class, false);
    }

    @Path("/info")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public OAuth2User getUserInfo(@HeaderParam("token") String token, @HeaderParam("provider") String provider, @Context HttpServletRequest req) {
        if (token == null || token.isEmpty()) {
            throw new WebApplicationException(Response.status(412).entity(new ErrorEntity("token is required")).build());
        }
        if (provider == null || provider.isEmpty()) {
            throw new WebApplicationException(Response.status(412).entity(new ErrorEntity("provider is required")).build());
        }
        OAuth2InfoProvider infoProvider = null;
        Iterator<OAuth2ProviderMetaData> iterator = oAuth2ProviderMetaDataList.iterator();
        while (infoProvider == null && iterator.hasNext()) {
            OAuth2ProviderMetaData metaData = iterator.next();
            if (provider.equals(metaData.getName())) {
                infoProvider = metaData.getInfoProvider();
            }
        }
        OAuth2User result = null;
        if (infoProvider != null) {
            Token authToken = new Token(token, "", "Octopus");

            result = infoProvider.retrieveUserInfo(authToken, req);
            if (result != null) {
                result.setLocalId(externalInternalIdMapper.getLocalId(result.getId()));
            }
        }
        return result;
    }

    @Path("/authenticate")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public UserToken returnUserToken() {
        return new UserToken(userPrincipal.getInfo().get("token").toString());
    }

    private static class UserToken {
        private String token;

        public UserToken(String token) {
            this.token = token;
        }

        public String getToken() {
            return token;
        }
    }
}
