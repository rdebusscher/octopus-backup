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
package be.c4j.ee.security.credentials.authentication.oauth2.github.servlet;


import be.c4j.ee.security.credentials.authentication.oauth2.github.GithubProvider;
import be.c4j.ee.security.credentials.authentication.oauth2.info.OAuth2InfoProvider;
import be.c4j.ee.security.credentials.authentication.oauth2.servlet.OAuth2CallbackProcessor;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 *
 */
public class GithubOAuth2CallbackProcessor extends OAuth2CallbackProcessor {

    @Inject
    @GithubProvider
    private OAuth2InfoProvider infoProvider;

    @Override
    public void processCallback(HttpServletRequest request, HttpServletResponse response) throws IOException {

        //Check if the user have rejected
        String error = request.getParameter("error");
        // Fixme check if this is the correct answer by Github
        if ((null != error) && ("access_denied".equals(error.trim()))) {
            logger.warn("Github informs us that no valid credentials are supplied or that consent is not given");
            HttpSession sess = request.getSession();
            sess.invalidate();
            response.sendRedirect(request.getContextPath());
            return;
        }

        if (!checkCSRFToken(request, response)) {
            return;
        }

        //OK the user have consented so lets process authentication within Octopus/Shiro
        doAuthenticate(request, response, infoProvider);
    }

}
