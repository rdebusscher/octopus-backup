package be.c4j.ee.security.util;

import javax.enterprise.context.ApplicationScoped;
import javax.servlet.http.HttpServletRequest;

/**
 *
 *
 */
@ApplicationScoped
public class URLUtil {

    public String determineRoot(HttpServletRequest req) {
        // FIXME Duplicate with OAuth2ServiceProducer
        StringBuilder result = new StringBuilder();
        result.append(req.getScheme()).append("://");
        result.append(req.getServerName()).append(':');
        result.append(req.getServerPort());
        result.append(req.getContextPath());
        return result.toString();
    }

}
