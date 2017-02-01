package be.c4j.ee.security.filter.shiro;

import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;

import javax.servlet.FilterConfig;

/**
 */

public class OctopusPathMatchingFilterChainResolver extends PathMatchingFilterChainResolver {

    public OctopusPathMatchingFilterChainResolver() {
        super();
        setFilterChainManager(new OctopusFilterChainManager());
    }

    public OctopusPathMatchingFilterChainResolver(FilterConfig filterConfig) {
        super(filterConfig);
        setFilterChainManager(new OctopusFilterChainManager(filterConfig));
    }


}
