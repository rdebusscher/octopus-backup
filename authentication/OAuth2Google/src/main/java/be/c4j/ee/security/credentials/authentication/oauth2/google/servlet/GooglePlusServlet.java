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
package be.c4j.ee.security.credentials.authentication.oauth2.google.servlet;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2Configuration;
import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2SessionAttributes;
import be.c4j.ee.security.credentials.authentication.oauth2.csrf.CSRFTokenProducer;
import be.c4j.ee.security.credentials.authentication.oauth2.google.provider.GoogleOAuth2ServiceProducer;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 *
 */
@WebServlet("/googleplus")
public class GooglePlusServlet extends HttpServlet {

    @Inject
    private GoogleOAuth2ServiceProducer googleOAuth2ServiceProducer;

    @Inject
    private CSRFTokenProducer csrfTokenProducer;

    @Inject
    private OAuth2SessionAttributes oAuth2SessionAttributes;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, ServletException {

        String token = csrfTokenProducer.nextToken();
        OAuth20Service service = googleOAuth2ServiceProducer.createOAuthService(req, token);

        oAuth2SessionAttributes.setOAuth2Service(req, service);
        oAuth2SessionAttributes.setCSRFToken(req, token);
        oAuth2SessionAttributes.setApplication(req, req.getParameter(OAuth2Configuration.APPLICATION));

        String authorizationUrl = service.getAuthorizationUrl();
        resp.sendRedirect(authorizationUrl);
    }


}

