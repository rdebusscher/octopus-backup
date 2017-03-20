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
package be.c4j.ee.security.credentials.authentication.cas;

import be.c4j.ee.security.authentication.ActiveSessionRegistry;
import be.c4j.ee.security.config.OctopusJSFConfig;
import be.c4j.ee.security.credentials.authentication.cas.info.CasInfoProvider;
import be.c4j.ee.security.exception.OctopusUnexpectedException;
import be.c4j.ee.security.session.SessionUtil;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;
import org.jasig.cas.client.util.XmlUtils;

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
@WebServlet(urlPatterns = {"/cas-callback"})
public class CasCallbackServlet extends HttpServlet {

    // the name of the parameter service ticket in url
    private static final String TICKET_PARAMETER = "ticket";

    @Inject
    private CasInfoProvider casInfoProvider;

    @Inject
    private OctopusJSFConfig octopusConfig;

    @Inject
    private ActiveSessionRegistry activeSessionRegistry;

    @Inject
    private SessionUtil sessionUtil;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        String ticket = request.getParameter(TICKET_PARAMETER);

        CasUser casUser = null;
        HttpSession sess = request.getSession();
        try {
            casUser = casInfoProvider.retrieveUserInfo(ticket);

            sessionUtil.invalidateCurrentSession(request);

            SecurityUtils.getSubject().login(casUser);

            activeSessionRegistry.startSession(ticket, SecurityUtils.getSubject().getPrincipal());
            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(request);
            try {
                response.sendRedirect(savedRequest != null ? savedRequest.getRequestUrl() : request.getContextPath());
            } catch (IOException e) {
                // OWASP A6 : Sensitive Data Exposure
                throw new OctopusUnexpectedException(e);
                // FIXME see that we cache this at the filter and it never gets exposed to the client
            }

        } catch (AuthenticationException e) {
            sess.setAttribute(CasUser.CAS_USER_INFO, casUser);
            sess.setAttribute("AuthenticationExceptionMessage", e.getMessage());
            // DataSecurityProvider decided that google user has no access to application
            try {
                response.sendRedirect(request.getContextPath() + octopusConfig.getUnauthorizedExceptionPage());
            } catch (IOException ioException) {
                // OWASP A6 : Sensitive Data Exposure
                throw new OctopusUnexpectedException(ioException);
            }
        }
    }

    @Override
    protected void doPost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
        String logoutRequest = httpServletRequest.getParameter("logoutRequest");

        if (logoutRequest != null && logoutRequest.length() > 0) {
            if (logoutRequest.startsWith("<samlp:LogoutRequest")) {
                String sessionIdentifier = XmlUtils.getTextForElement(logoutRequest, "SessionIndex");
                activeSessionRegistry.endSession(sessionIdentifier);
            }
        }
        // TODO Do we need some logging when we receive post requests which doesn't contain the correct logout protocol?

    }
}
