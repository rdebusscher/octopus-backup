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

import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.sso.server.config.SSOServerConfiguration;
import be.c4j.ee.security.sso.server.store.SSOTokenStore;

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

@WebServlet("/octopus/sso/logout")
public class LogoutServlet extends HttpServlet {

    @Inject
    private SSOServerConfiguration ssoServerConfiguration;

    @Inject
    private UserPrincipal userPrincipal;

    @Inject
    private SSOTokenStore tokenStore;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        System.out.println(userPrincipal);

        deleteCookie(resp);
    }

    private void deleteCookie(HttpServletResponse resp) {
        Cookie cookie = new Cookie(ssoServerConfiguration.getSSOCookieName(), ""); // Cleared
        cookie.setComment("Octopus SSO token");

        cookie.setHttpOnly(true);
        cookie.setSecure(Boolean.valueOf(ssoServerConfiguration.getSSOCookieSecure()));
        cookie.setMaxAge(0); // 0 -> delete
        resp.addCookie(cookie);

    }
}