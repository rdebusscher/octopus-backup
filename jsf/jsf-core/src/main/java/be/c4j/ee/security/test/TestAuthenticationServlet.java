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
@WebServlet("/testAuthentication")
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
            httpServletResponse.sendRedirect(referer + '?' + OctopusConstants.OCTOPUS_AUTHENTICATED + '=' + subject.isAuthenticated());
        }
    }
}
