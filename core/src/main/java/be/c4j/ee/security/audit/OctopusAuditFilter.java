package be.c4j.ee.security.audit;

import org.apache.deltaspike.core.api.provider.BeanManagerProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.web.filter.PathMatchingFilter;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 *
 */
public class OctopusAuditFilter extends PathMatchingFilter {

    @Override
    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        ShiroHttpServletRequest servletRequest = (ShiroHttpServletRequest) request;
        if (!"partial/ajax".equals(servletRequest.getHeader("Faces-Request"))) {
            Object principal = SecurityUtils.getSubject().getPrincipal();
            String requestURI = servletRequest.getRequestURI();
            int idx = requestURI.indexOf('/', 2);
            if (idx > 0) {
                requestURI = requestURI.substring(idx);
            }
            String remoteAddress = servletRequest.getRemoteAddr();

            BeanManagerProvider.getInstance().getBeanManager().fireEvent(new OctopusAuditEvent(requestURI, principal, remoteAddress));
        }


        return true;
    }
}
