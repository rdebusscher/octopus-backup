package be.c4j.ee.security.shiro;

import be.c4j.ee.security.exception.OctopusUnauthorizedException;
import org.apache.shiro.web.filter.authc.UserFilter;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
public class RestUserFilter extends UserFilter {

    /**
     * Overrides the default behavior to show and swallow the exception if the exception is
     * {@link org.apache.shiro.authz.UnauthenticatedException}.
     */
    @Override
    protected void cleanup(ServletRequest request, ServletResponse response, Exception existing) throws ServletException, IOException {
        Throwable unauthorized = OctopusUnauthorizedException.getUnauthorizedException(existing);
        if (unauthorized != null) {
            try {
                ((HttpServletResponse) response).setStatus(401);
                response.getOutputStream().println(unauthorized.getMessage());
                existing = null;
            } catch (Exception e) {
                existing = e;
            }
        }
        super.cleanup(request, response, existing);

    }
}
