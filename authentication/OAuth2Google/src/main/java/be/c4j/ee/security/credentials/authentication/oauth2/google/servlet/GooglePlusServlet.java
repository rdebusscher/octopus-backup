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
package be.c4j.ee.security.credentials.authentication.oauth2.google.servlet;

import be.c4j.ee.security.credentials.authentication.oauth2.google.provider.GoogleOAuth2ServiceProducer;
import be.c4j.ee.security.credentials.authentication.oauth2.servlet.OAuth2Servlet;
import be.c4j.ee.security.exception.OctopusUnexpectedException;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@WebServlet("/googleplus")
public class GooglePlusServlet extends OAuth2Servlet {

    @Inject
    private GoogleOAuth2ServiceProducer googleOAuth2ServiceProducer;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            redirectToAuthorizationURL(request, response, googleOAuth2ServiceProducer);
        } catch (IOException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new OctopusUnexpectedException(e);

        }
    }

    @Override
    protected String postProcessAuthorizationUrl(HttpServletRequest request, String authorizationUrl) {
        String result = authorizationUrl;
        boolean multipleAccounts = false;
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (MultipleAccountServlet.OCTOPUS_GOOGLE_MULTIPLE_ACCOUNTS.equals(cookie.getName())) {
                    multipleAccounts = true;
                }
            }
        }
        if (multipleAccounts) {
            result += "&prompt=select_account";
        }
        return result;
    }
}

