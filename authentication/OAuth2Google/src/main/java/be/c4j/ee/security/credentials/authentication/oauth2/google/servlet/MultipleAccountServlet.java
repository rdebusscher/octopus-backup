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

import be.c4j.ee.security.exception.OctopusUnexpectedException;

import javax.enterprise.inject.Instance;
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
@WebServlet("/usingMultipleAccounts")
public class MultipleAccountServlet extends HttpServlet {

    public static final String OCTOPUS_GOOGLE_MULTIPLE_ACCOUNTS = "OctopusGoogleMultipleAccounts";

    @Inject
    private Instance<MultipleAccountContent> multipleAccountContent;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        Boolean usingMultiple = Boolean.valueOf(request.getParameter("value"));
        setMultipleAccountCookie(response, !usingMultiple);
        if (!multipleAccountContent.isUnsatisfied()) {
            multipleAccountContent.get().doGet(request, response);
        } else {
            try {
                response.getWriter().write("Octopus : Multiple accounts for google is active ? " + usingMultiple);
            } catch (IOException e) {
                // OWASP A6 : Sensitive Data Exposure
                throw new OctopusUnexpectedException(e);

            }
        }
    }

    private void setMultipleAccountCookie(HttpServletResponse response, boolean remove) {
        Cookie cookie = new Cookie(OCTOPUS_GOOGLE_MULTIPLE_ACCOUNTS, "true");
        cookie.setComment("Triggers the account chooser from Google");
        if (remove) {
            cookie.setMaxAge(0);
        } else {

            cookie.setMaxAge(60 * 60 * 24 * 365 * 10); // 10 year
        }
        response.addCookie(cookie);
    }

}
