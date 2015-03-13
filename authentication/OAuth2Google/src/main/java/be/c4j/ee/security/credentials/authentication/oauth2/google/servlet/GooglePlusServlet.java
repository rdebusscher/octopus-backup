package be.c4j.ee.security.credentials.authentication.oauth2.google.servlet;

import be.c4j.ee.security.credentials.authentication.oauth2.google.provider.GoogleOAuth2ServiceProducer;
import org.scribe.oauth.OAuthService;

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
@WebServlet("/googleplus")
public class GooglePlusServlet extends HttpServlet {

    public static final String APPLICATION = "application";

    @Inject
    private GoogleOAuth2ServiceProducer googleOAuth2ServiceProducer;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, ServletException {

        OAuthService service = googleOAuth2ServiceProducer.createOAuthService(req);

        HttpSession sess = req.getSession();
        sess.setAttribute("oauth2Service", service);

        sess.setAttribute(APPLICATION, req.getParameter(APPLICATION));
        resp.sendRedirect(service.getAuthorizationUrl(null));
    }


}

