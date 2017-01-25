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
package be.c4j.ee.security.credentials.authentication.oauth2;

import com.github.scribejava.core.oauth.OAuth20Service;

import javax.enterprise.context.ApplicationScoped;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 *
 */
@ApplicationScoped
public class OAuth2SessionAttributes {

    private static final String OAUTH2_SERVICE = "oauth2Service";
    private static final String CSRF_TOKEN = "csrfToken";

    public void setOAuth2Service(HttpServletRequest request, OAuth20Service service) {
        HttpSession session = request.getSession();
        session.setAttribute(OAUTH2_SERVICE, service);
    }

    public void setCSRFToken(HttpServletRequest request, String token) {
        HttpSession session = request.getSession();
        session.setAttribute(CSRF_TOKEN, token);
    }

    public void setApplication(HttpServletRequest request, String applicationName) {
        HttpSession session = request.getSession();
        session.setAttribute(OAuth2Configuration.APPLICATION, applicationName);
    }

    public OAuth20Service getOAuth2Service(HttpServletRequest request) {
        HttpSession session = request.getSession();
        return (OAuth20Service) session.getAttribute(OAUTH2_SERVICE);
    }

    public String getCSRFToken(HttpServletRequest request) {
        HttpSession session = request.getSession();
        return (String) session.getAttribute(CSRF_TOKEN);
    }

    public String getApplication(HttpServletRequest request) {
        HttpSession session = request.getSession();
        return (String) session.getAttribute(OAuth2Configuration.APPLICATION);
    }

}
