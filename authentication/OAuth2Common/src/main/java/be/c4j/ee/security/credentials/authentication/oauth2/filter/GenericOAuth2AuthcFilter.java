package be.c4j.ee.security.credentials.authentication.oauth2.filter;

import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
public class GenericOAuth2AuthcFilter extends BasicHttpAuthenticationFilter implements Initializable {

    public static final String OAUTH2_PROVIDER = "provider";

    private OAuth2AuthcFilterManager filterManager;

    public GenericOAuth2AuthcFilter() {
        setAuthcScheme("Multiple provider OAuth2");
        setAuthzScheme("Bearer");
    }

    @Override
    public void init() throws ShiroException {
        filterManager = BeanProvider.getContextualReference(OAuth2AuthcFilterManager.class);
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        HttpServletRequest httpRequest = WebUtils.toHttp(request);
        String provider = httpRequest.getHeader(OAUTH2_PROVIDER);
        AbstractOAuth2AuthcFilter filter = filterManager.getFilterForProvider(provider);

        AuthenticationToken result = null;
        if (filter != null) {
            result = filter.createToken(request, response);
        }
        return result;
    }
}