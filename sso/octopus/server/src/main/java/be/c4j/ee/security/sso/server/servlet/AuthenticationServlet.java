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

import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import be.c4j.ee.security.sso.server.ApplicationCallback;
import be.c4j.ee.security.sso.server.SSOProducerBean;
import be.c4j.ee.security.sso.server.config.SSOServerConfiguration;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@WebServlet("/octopus/sso/authenticate")
public class AuthenticationServlet extends HttpServlet {

    @Inject
    private SSOServerConfiguration ssoServerConfiguration;

    @Inject
    private SSOProducerBean ssoProducerBean;

    private SSODataEncryptionHandler encryptionHandler;

    @Inject
    private ApplicationCallback applicationCallback;

    @Inject
    private SSOTokenStore tokenStore;

    @Override
    public void init() throws ServletException {
        super.init();
        encryptionHandler = BeanProvider.getContextualReference(SSODataEncryptionHandler.class, true);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // We can't inject the OctopusSSOUSer because we then get a Proxy which is stored.
        // Bad things will happen ....
        OctopusSSOUser ssoUser = ssoProducerBean.getOctopusSSOUser();
        tokenStore.keepToken(ssoUser);

        String apiKey = req.getParameter("apiKey");
        String application = req.getParameter("application");
        if (encryptionHandler != null) {
            application = encryptionHandler.decryptData(req.getParameter("application"), apiKey);
        }
        String callback = applicationCallback.determineCallback(application) + "/octopus/sso/SSOCallback";
        String token = createToken(ssoUser, apiKey);
        callback += "?token=" + token;
        try {
            attachCookie(resp, ssoUser.getToken());

            resp.sendRedirect(callback);

            req.getSession().invalidate();  // Don't keep the session on the SSO server
        } catch (IOException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new OctopusUnexpectedException(e);

        }
    }

    private void attachCookie(HttpServletResponse resp, String token) {
        Cookie cookie = new Cookie(ssoServerConfiguration.getSSOCookieName(), token);
        cookie.setComment("Octopus SSO token");

        cookie.setHttpOnly(true);
        cookie.setSecure(Boolean.valueOf(ssoServerConfiguration.getSSOCookieSecure()));
        cookie.setMaxAge(ssoServerConfiguration.getSSOCookieTimeToLive() * 60 * 60); // Hours -> Seconds
        resp.addCookie(cookie);
    }

    private String createToken(OctopusSSOUser ssoUser, String apiKey) {
        String result;
        String token = ssoUser.getToken();
        if (encryptionHandler != null) {
            result = encryptionHandler.encryptData(token, apiKey);
        } else {
            result = token;
        }
        return result;

    }
}
