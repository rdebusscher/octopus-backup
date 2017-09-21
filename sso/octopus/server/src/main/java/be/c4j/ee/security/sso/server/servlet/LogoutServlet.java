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
import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.server.client.ClientInfo;
import be.c4j.ee.security.sso.server.client.ClientInfoRetriever;
import be.c4j.ee.security.sso.server.store.OIDCStoreData;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import org.apache.shiro.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

/**
 *
 */

@WebServlet("/octopus/sso/logout")
public class LogoutServlet extends HttpServlet {

    private Logger logger = LoggerFactory.getLogger(LogoutServlet.class);

    @Inject
    private OctopusSSOUser octopusSSOUser;

    @Inject
    private OctopusJSFConfig jsfConfiguration;

    @Inject
    private OctopusConfig octopusConfig;

    @Inject
    private SSOTokenStore tokenStore;

    @Inject
    private ClientInfoRetriever clientInfoRetriever;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse resp) throws ServletException, IOException {
        LogoutRequest logoutRequest;
        try {
            logoutRequest = LogoutRequest.parse(request.getQueryString());
        } catch (ParseException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new OctopusUnexpectedException(e);
            // TODO What should we return (check spec)
        }

        if (!validRequest((SignedJWT) logoutRequest.getIDTokenHint())) {
            return; // Just ignore when an invalid requests comes in.
        }
        String clientId = getClientId(logoutRequest.getIDTokenHint());

        doSingleLogout(clientId);

        tokenStore.removeUser(octopusSSOUser);

        try {
            resp.sendRedirect(getLogoutURL(request));
        } catch (IOException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new OctopusUnexpectedException(e);
        }

        SecurityUtils.getSubject().logout();

        showDebugInfo(octopusSSOUser);

    }

    private String getClientId(JWT idTokenHint) {
        return idTokenHint.getHeader().getCustomParam("clientId").toString();
    }

    private boolean validRequest(SignedJWT idTokenHint) {
        if (idTokenHint == null) {
            return false;
        }

        try {
            String clientId = idTokenHint.getHeader().getCustomParam("clientId").toString();
            ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(clientId);
            if (clientInfo == null) {
                return false;
            }

            byte[] clientSecret = new Base64(clientInfo.getClientSecret()).decode();
            MACVerifier verifier = new MACVerifier(clientSecret);
            if (!idTokenHint.verify(verifier)) {
                return false;
            }

            if (!clientId.equals(idTokenHint.getJWTClaimsSet().getSubject())) {
                return false;
            }

            return !idTokenHint.getJWTClaimsSet().getExpirationTime().before(new Date());
        } catch (JOSEException e) {
            // TODO Log this
            return false;
        } catch (java.text.ParseException e) {
            // TODO Log this
            return false;
        }
    }

    private void doSingleLogout(String clientId) {
        List<OIDCStoreData> loggedInClients = tokenStore.getLoggedInClients(octopusSSOUser);

        OIDCStoreData loggedInClient;
        Iterator<OIDCStoreData> iterator = loggedInClients.iterator();
        while (iterator.hasNext()) {
            loggedInClient = iterator.next();
            if (clientId.equals(loggedInClient.getClientId().getValue())) {
                iterator.remove();
            } else {

                ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(loggedInClient.getClientId().getValue());
                // FIXME use clientInfo.isOctopusClient
                String url = clientInfo.getCallbackURL() + "/octopus/sso/SSOLogoutCallback?access_token=" + loggedInClient.getAccessToken().getValue();
                sendLogoutRequestToClient(url);
            }
        }
    }

    private void sendLogoutRequestToClient(String url) {
        try {
            URL obj = new URL(url);
            HttpURLConnection con = (HttpURLConnection) obj.openConnection();

            // optional default is GET
            con.setRequestMethod("GET");

            //add request header
            //con.setRequestProperty("User-Agent", USER_AGENT);

            int responseCode = con.getResponseCode();
            if (responseCode != 200) {
                logger.warn(String.format("Sending logout request to %s failed with status :  %s, message : %s", url, responseCode, con.getResponseMessage()));
            }
        } catch (IOException e) {
            logger.warn(String.format("Sending logout request to %s failed with %s", url, e.getMessage()));
        }
    }

    private String getLogoutURL(HttpServletRequest request) {

        String result;
        String logoutPage = jsfConfiguration.getLogoutPage();
        if (logoutPage.startsWith("/")) {
            result = getRootUrl(request) + logoutPage;
        } else {
            result = logoutPage;
        }
        return result;
    }

    private String getRootUrl(HttpServletRequest request) {
        return request.getContextPath();
    }

    private void showDebugInfo(OctopusSSOUser user) {

        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("(SSO Server) User %s is logged out (cookie token = %s)", user.getFullName(), user.getCookieToken()));
        }
    }
}