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
 *
 */
package be.c4j.ee.security.sso.server;

import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;
import org.apache.deltaspike.core.api.provider.BeanProvider;

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

    @Inject
    private UserPrincipal userPrincipal;

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
        tokenStore.keepToken((OctopusSSOUser) userPrincipal.getInfo().get(OctopusSSOUser.USER_INFO_KEY));

        String apiKey = req.getParameter("apiKey");
        String application = encryptionHandler.decryptData(req.getParameter("application"), apiKey);
        String callback = applicationCallback.determineCallback(application);
        String token = createToken(apiKey);
        callback += "?token=" + token;
        resp.sendRedirect(callback);
    }

    private String createToken(String apiKey) {
        String result;
        String token = userPrincipal.getInfo().get("token").toString();
        if (encryptionHandler != null) {
            result = encryptionHandler.encryptData(token, apiKey);
        } else {
            result = token;
        }
        return result;

    }
}
