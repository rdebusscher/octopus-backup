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
package be.c4j.ee.security.test;

import be.c4j.ee.security.OctopusConstants;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.RedirectView;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;

import static javax.servlet.http.HttpServletResponse.SC_PRECONDITION_FAILED;

/**
 *
 */
@WebServlet("/octopus/testAuthentication")
public class TestAuthenticationServlet extends HttpServlet {

    @Inject
    private Subject subject;

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {

        String parameter = httpServletRequest.getParameter(OctopusConstants.OCTOPUS_REFERER);
        if (parameter == null) {
            httpServletResponse.sendError(SC_PRECONDITION_FAILED, "Missing query parameter");
        } else {
            String referer = URLDecoder.decode(parameter, RedirectView.DEFAULT_ENCODING_SCHEME);
            httpServletResponse.sendRedirect(referer + '?' + OctopusConstants.OCTOPUS_AUTHENTICATED + '=' + isKnown());
        }
    }

    private boolean isKnown() {
        return subject.isRemembered() || subject.isAuthenticated();
    }
}
