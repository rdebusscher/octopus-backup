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
import be.c4j.ee.security.sso.SSOFlow;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import be.c4j.ee.security.sso.server.SSOProducerBean;
import be.c4j.ee.security.sso.server.client.ClientInfoRetriever;
import be.c4j.ee.security.sso.server.config.SSOServerConfiguration;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import org.apache.deltaspike.core.api.provider.BeanProvider;
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
@WebServlet("/octopus/sso/authenticate")
public class AuthenticationServlet extends HttpServlet {

    private Logger logger = LoggerFactory.getLogger(AuthenticationServlet.class);

    @Inject
    private SSOServerConfiguration ssoServerConfiguration;

    @Inject
    private SSOProducerBean ssoProducerBean;

    @Inject
    private SSOTokenStore tokenStore;

    private SSODataEncryptionHandler encryptionHandler;

    @Inject
    private ClientInfoRetriever clientInfoRetriever;

    @Inject
    private OctopusConfig octopusConfig;

    @Override
    public void init() throws ServletException {
        super.init();
        encryptionHandler = BeanProvider.getContextualReference(SSODataEncryptionHandler.class, true);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // We can't inject the OctopusSSOUSer because we then get a Proxy which is stored.
        // Bad things will happen ....
        OctopusSSOUser ssoUser = ssoProducerBean.getOctopusSSOUser();

        String apiKey = request.getParameter("apiKey");
        String clientId = request.getParameter("client_id");
        String responseType = request.getParameter("response_type");
        String state = request.getParameter("state");

        tokenStore.addLoginFromClient(ssoUser, clientId);

        // clientId is never encrypted
        String callback = clientInfoRetriever.retrieveInfo(clientId).getCallbackURL() + "/octopus/sso/SSOCallback";

        SSOFlow ssoFlow = SSOFlow.defineFlow(responseType);

        String code = createCode(ssoUser, apiKey, ssoFlow);
        // Code can optionally be wrapped in JWT (only when implicit and encryption handler is available)

        callback += determineParametersCallback(ssoFlow, code, state);

        try {

            showDebugInfo(ssoUser);
            response.sendRedirect(callback);

            request.getSession().invalidate();  // Don't keep the session on the SSO server
            //SecurityUtils.getSubject().logout();// Do not use logout of subject, it wil remove the cookie which we need !
        } catch (IOException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new OctopusUnexpectedException(e);

        }
    }

    private String determineParametersCallback(SSOFlow ssoFlow, String code, String state) {
        StringBuilder result = new StringBuilder();
        switch (ssoFlow) {

            case IMPLICIT:
                result.append("?access_token=").append(code);
                break;
            case AUTHORIZATION_CODE:
                result.append("?code=").append(code);
                break;
        }
        result.append("&state=").append(state);
        return result.toString();
    }

    private void showDebugInfo(OctopusSSOUser user) {
        if (octopusConfig.showDebugFor().contains(Debug.SSO_FLOW)) {
            logger.info(String.format("User %s is authenticated and cookie written if needed.", user.getFullName()));
        }
    }

    private String createCode(OctopusSSOUser ssoUser, String apiKey, SSOFlow ssoFlow) {
        String result;
        String token = ssoUser.getToken();
        if (ssoFlow == SSOFlow.IMPLICIT) {
            // Only in IMPLICIT mode we can have an encrypted Token
            if (encryptionHandler != null) {
                result = encryptionHandler.encryptData(token, apiKey);
            } else {
                result = token;
            }
        } else {
            result = token;
        }
        return result;

    }
}
