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
package be.c4j.ee.security.sso.server.servlet;

import be.c4j.ee.security.config.Debug;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.server.client.ClientInfoRetriever;
import be.c4j.ee.security.sso.server.config.SSOServerConfiguration;
import be.c4j.ee.security.sso.server.store.OIDCStoreData;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@WebServlet("/octopus/sso/token")
public class TokenServlet extends HttpServlet {

    private Logger logger = LoggerFactory.getLogger(TokenServlet.class);

    @Inject
    private OctopusSSOUser ssoUser;

    @Inject
    private SSOServerConfiguration ssoServerConfiguration;

    @Inject
    private SSOTokenStore tokenStore;

    @Inject
    private ClientInfoRetriever clientInfoRetriever;

    @Inject
    private OctopusConfig octopusConfig;

    @Override
    public void init() throws ServletException {
        super.init();
    }

    @Override
    protected void doPost(HttpServletRequest httpServletRequest, HttpServletResponse response) throws ServletException, IOException {

        TokenRequest tokenRequest = (TokenRequest) httpServletRequest.getAttribute(AbstractRequest.class.getName());

        AccessTokenResponse tokenResponse = null;
        AuthorizationGrant grant = tokenRequest.getAuthorizationGrant();

        try {
            if (grant instanceof AuthorizationCodeGrant) {
                tokenResponse = defineResponse((AuthorizationCodeGrant) grant);

            }

            if (tokenResponse != null) {
                response.setContentType("application/json");

                JSONObject jsonObject = tokenResponse.toJSONObject();
                response.getWriter().append(jsonObject.toJSONString());
            }
        } catch (Exception e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new OctopusUnexpectedException(e);
        }
        /*

        /*
        String query = request.getQueryString();
        */
    }

    private AccessTokenResponse defineResponse(AuthorizationCodeGrant codeGrant) throws ParseException {
        AuthorizationCode authorizationCode = codeGrant.getAuthorizationCode();

        OIDCStoreData oidcStoreData = tokenStore.getOIDCDataByAuthorizationCode(authorizationCode);

        // FIXME Config
        PlainJWT plainJWT = new PlainJWT(oidcStoreData.getIdTokenClaimsSet().toJWTClaimsSet());

        OIDCTokens token = new OIDCTokens(plainJWT, oidcStoreData.getAccessCode(), null); // FIXME refresh tokens
        return new OIDCTokenResponse(token);
    }

    private void showDebugInfo(OctopusSSOUser user) {
        // FIXME Correct logging
        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("User %s is authenticated and cookie written if needed.", user.getFullName()));
        }
    }
}
