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
package be.c4j.ee.security.credentials.authentication.oauth2.servlet;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2Configuration;
import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2SessionAttributes;
import be.c4j.ee.security.credentials.authentication.oauth2.csrf.CSRFTokenProducer;
import be.c4j.ee.security.credentials.authentication.oauth2.fake.EmailControl;
import be.c4j.ee.security.credentials.authentication.oauth2.fake.FakeOAuth2Authentication;
import be.c4j.ee.security.credentials.authentication.oauth2.provider.OAuth2ServiceProducer;
import com.github.scribejava.core.oauth.OAuth20Service;
import org.apache.deltaspike.core.api.provider.BeanProvider;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
public class OAuth2Servlet extends HttpServlet {

    @Inject
    private CSRFTokenProducer csrfTokenProducer;

    @Inject
    private OAuth2SessionAttributes oAuth2SessionAttributes;

    @Inject
    private EmailControl emailControl;

    private FakeOAuth2Authentication fakeOAuth2Authentication;

    @Override
    public void init() throws ServletException {
        super.init();

        fakeOAuth2Authentication = BeanProvider.getContextualReference(FakeOAuth2Authentication.class, true);
    }

    protected void redirectToAuthorizationURL(HttpServletRequest request, HttpServletResponse response, OAuth2ServiceProducer serviceProducer) throws IOException {
        String userParameter = request.getParameter(OAuth2Configuration.USER);
        if (fakeOAuth2Authentication != null && emailControl.isValidEmail(userParameter)) {
            boolean handled = fakeOAuth2Authentication.forwardForTokenCreation(getServletContext(), request, response, userParameter);
            if (handled) {
                return;
            } else {
                response.sendError(404, "Fake user data incorrect");
            }
        }

        String token = csrfTokenProducer.nextToken();
        OAuth20Service service = serviceProducer.createOAuthService(request, token);

        oAuth2SessionAttributes.setOAuth2Service(request, service);
        oAuth2SessionAttributes.setCSRFToken(request, token);

        String authorizationUrl = service.getAuthorizationUrl();
        response.sendRedirect(postProcessAuthorizationUrl(request, authorizationUrl));
    }

    protected String postProcessAuthorizationUrl(HttpServletRequest request, String authorizationUrl) {
        return authorizationUrl;
    }

}
