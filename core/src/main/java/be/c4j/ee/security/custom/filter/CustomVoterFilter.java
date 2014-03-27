package be.c4j.ee.security.custom.filter;

import be.c4j.ee.security.custom.AbstractGenericVoter;
import be.c4j.ee.security.view.InvocationContextImpl;
import org.apache.myfaces.extensions.cdi.core.api.provider.BeanManagerProvider;
import org.apache.myfaces.extensions.cdi.core.impl.util.CodiUtils;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;

import javax.enterprise.inject.spi.BeanManager;
import javax.interceptor.InvocationContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
public class CustomVoterFilter extends AuthorizationFilter {


    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {


        String[] voters = (String[]) mappedValue;

        BeanManager bm = BeanManagerProvider.getInstance().getBeanManager();

        String url = ((HttpServletRequest) request).getRequestURL().toString();
        InvocationContext ic = new InvocationContextImpl(url, new Object[]{request});

        boolean permitted = true;

        for (String voter : voters) {
            AbstractGenericVoter voterObj = CodiUtils.getContextualReferenceByName(bm, voter, AbstractGenericVoter.class);
            if (!voterObj.verify(ic)) {
                permitted = false;
                break;
            }
        }
        return permitted;

    }
}
