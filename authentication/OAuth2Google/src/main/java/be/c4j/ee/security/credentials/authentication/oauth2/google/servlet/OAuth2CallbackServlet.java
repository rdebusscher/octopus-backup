package be.c4j.ee.security.credentials.authentication.oauth2.google.servlet;


import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.credentials.authentication.oauth2.google.GoogleUser;
import be.c4j.ee.security.credentials.authentication.oauth2.google.json.GoogleJSONProcessor;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;
import org.scribe.model.*;
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
@WebServlet(urlPatterns = {"/oauth2callback"})
public class OAuth2CallbackServlet extends HttpServlet {

    @Inject
    private GoogleJSONProcessor jsonProcessor;

    @Inject
    private OctopusConfig octopusConfig;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, ServletException {

        //Check if the user have rejected
        String error = req.getParameter("error");
        if ((null != error) && ("access_denied".equals(error.trim()))) {
            HttpSession sess = req.getSession();
            sess.invalidate();
            resp.sendRedirect(req.getContextPath());
            return;
        }

        //OK the user have consented so lets find out about the user

        HttpSession sess = req.getSession();
        OAuthService service = (OAuthService) sess.getAttribute("oauth2Service");

        //Get the all important authorization code
        String code = req.getParameter("code");
        //Construct the access token
        Token token = service.getAccessToken(null, new Verifier(code));

        //Now do something with it - get the user's G+ profile
        OAuthRequest oReq = new OAuthRequest(Verb.GET,
                "https://www.googleapis.com/oauth2/v2/userinfo");
        service.signRequest(token, oReq);
        Response oResp = oReq.send();

        //Read the result

        GoogleUser googleUser = jsonProcessor.extractGoogleUser(oResp.getBody());

        sess.setAttribute("googleUser", googleUser);
        try {
            SecurityUtils.getSubject().login(googleUser);
            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(req);
            resp.sendRedirect(savedRequest != null ? savedRequest.getRequestUrl() : req.getContextPath());
        } catch (AuthenticationException e) {
            // DataSecurityProvider decided that google user has no access to application
            resp.sendRedirect(req.getContextPath() + octopusConfig.getUnauthorizedExceptionPage());
        }


    }
}
