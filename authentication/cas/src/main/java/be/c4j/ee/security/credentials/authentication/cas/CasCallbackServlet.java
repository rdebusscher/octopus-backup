package be.c4j.ee.security.credentials.authentication.cas;

import be.c4j.ee.security.config.OctopusConfig;
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
    private OctopusConfig octopusConfig;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, ServletException {

        String ticket = req.getParameter(TICKET_PARAMETER);

        CasUser casUser = casInfoProvider.retrieveUserInfo(ticket, req);
        HttpSession sess = req.getSession();

        try {

            SecurityUtils.getSubject().login(casUser);
            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(req);
            resp.sendRedirect(savedRequest != null ? savedRequest.getRequestUrl() : req.getContextPath());

        } catch (AuthenticationException e) {
            sess.setAttribute(CasUser.CAS_USER_INFO, casUser);
            sess.setAttribute("AuthenticationExceptionMessage", e.getMessage());
            // DataSecurityProvider decided that google user has no access to application
            resp.sendRedirect(req.getContextPath() + octopusConfig.getUnauthorizedExceptionPage());
        }
    }
}
