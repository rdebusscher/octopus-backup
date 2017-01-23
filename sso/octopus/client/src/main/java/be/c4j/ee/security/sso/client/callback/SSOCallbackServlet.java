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
package be.c4j.ee.security.sso.client.callback;

import be.c4j.ee.security.sso.OctopusSSOUser;
import be.c4j.ee.security.sso.client.config.OctopusSSOClientConfiguration;
import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;

/**
 *
 */
@WebServlet("/octopus/sso/SSOCallback")
public class SSOCallbackServlet extends HttpServlet {

    @Inject
    private SSODataEncryptionHandler encryptionHandler;

    @Inject
    private OctopusSSOClientConfiguration config;

    private Client client;

    @Override
    public void init() throws ServletException {

        client = ClientBuilder.newClient();
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse resp) throws ServletException, IOException {
        String realToken = retrieveToken(request);

        WebTarget target = client.target(config.getSSOServer() + "/" + config.getSSOEndpointRoot() + "/octopus/sso/user");

        Response response = target.request()
                .header("Authorization", "Bearer " + defineToken(realToken))
                .accept(MediaType.APPLICATION_JSON)
                .get();

        String json = response.readEntity(String.class);
        OctopusSSOUser user = OctopusSSOUser.fromJSON(json);

        response.close();

        user.setToken(realToken);

        try {
            SecurityUtils.getSubject().login(user);

            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(request);
            resp.sendRedirect(savedRequest != null ? savedRequest.getRequestUrl() : request.getContextPath());

        } catch (AuthenticationException e) {
            HttpSession sess = request.getSession();
            sess.setAttribute(OctopusSSOUser.USER_INFO_KEY, user);
            sess.setAttribute("AuthenticationExceptionMessage", e.getMessage());
            // DataSecurityProvider decided that Octopus user has no access to application
            resp.sendRedirect(request.getContextPath() + config.getUnauthorizedExceptionPage());
        }
    }

    private String defineToken(String token) {
        String result;
        if (encryptionHandler != null) {
            result = encryptionHandler.encryptData(token, null);
        } else {
            result = token;
        }
        return result;
    }

    private String retrieveToken(HttpServletRequest req) {
        String token = req.getParameter("token");
        String realToken;
        if (encryptionHandler != null) {

            realToken = encryptionHandler.decryptData(token, null);
        } else {
            realToken = token;
        }
        return realToken;
    }
}
