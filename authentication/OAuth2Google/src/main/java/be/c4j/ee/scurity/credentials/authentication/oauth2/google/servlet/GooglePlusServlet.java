package be.c4j.ee.scurity.credentials.authentication.oauth2.google.servlet;

import be.c4j.ee.scurity.credentials.authentication.oauth2.google.OAuth2GoogleConfiguration;
import be.c4j.ee.scurity.credentials.authentication.oauth2.google.scribe.Google2Api;
import org.scribe.builder.ServiceBuilder;
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

    @Inject
    private OAuth2GoogleConfiguration configuration;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, ServletException {

        //Configure
        ServiceBuilder builder = new ServiceBuilder();
        OAuthService service = builder.provider(Google2Api.class)
                .apiKey(configuration.getClientId())
                .apiSecret(configuration.getClientSecret())
                .callback(assembleCallbackUrl(req))
                .scope("openid profile email " +
                        "https://www.googleapis.com/auth/plus.login " +
                        "https://www.googleapis.com/auth/plus.me")
                .debug()
                .build(); //Now build the call

        HttpSession sess = req.getSession();
        sess.setAttribute("oauth2Service", service);

        resp.sendRedirect(service.getAuthorizationUrl(null));
    }

    private String assembleCallbackUrl(HttpServletRequest req) {
        StringBuilder result = new StringBuilder();
        result.append(req.getScheme()).append("://");
        result.append(req.getServerName()).append(':');
        result.append(req.getServerPort());
        result.append(req.getContextPath()).append("/oauth2callback");
        return result.toString();
    }

}

