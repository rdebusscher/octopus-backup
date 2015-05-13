package be.c4j.ee.security.credentials.authentication.oauth2;

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.credentials.authentication.oauth2.application.ApplicationInfo;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.web.filter.authc.UserFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 *
 */
public class OAuth2UserFilter extends UserFilter {

    private static final String FACES_REDIRECT_XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<partial-response><redirect url=\"%s\"></redirect></partial-response>";

    @Override
    protected void redirectToLogin(ServletRequest req, ServletResponse res) throws IOException {
        HttpServletRequest request = (HttpServletRequest) req;

        if ("partial/ajax".equals(request.getHeader("Faces-Request"))) {
            res.setContentType("text/xml");
            res.setCharacterEncoding("UTF-8");
            res.getWriter().printf(FACES_REDIRECT_XML, request.getContextPath() + getLoginUrl());
        } else {
            super.redirectToLogin(req, res);
        }
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        OctopusConfig config = BeanProvider.getContextualReference(OctopusConfig.class);
        Boolean postIsAllowedSavedRequest = Boolean.valueOf(config.getPostIsAllowedSavedRequest());

        HttpServletRequest req = (HttpServletRequest) request;
        if ("POST".equals(req.getMethod()) && !postIsAllowedSavedRequest) {
            redirectToLogin(request, response);
            return false;
        } else {
            return super.onAccessDenied(request, response);
        }
    }

    @Override
    public String getLoginUrl() {
        // FIXME Put these bean references at instance during the 'initialization'
        String result = "";
        ApplicationInfo applicationInfo = BeanProvider.getContextualReference(ApplicationInfo.class, true);
        if (applicationInfo != null) {
            result = '?' + OAuth2Configuration.APPLICATION + '=' + applicationInfo.getName();
        }
        OAuth2ServletInfo oAuth2ServletInfo = BeanProvider.getContextualReference(OAuth2ServletInfo.class);
        return oAuth2ServletInfo.getServletPath() + result;
    }
}
