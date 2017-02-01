package be.c4j.ee.security.filter.shiro;

import org.apache.shiro.web.filter.mgt.DefaultFilterChainManager;

import javax.servlet.FilterConfig;

/**
 */

public class OctopusFilterChainManager extends DefaultFilterChainManager {

    public OctopusFilterChainManager() {
        super();
    }

    public OctopusFilterChainManager(FilterConfig filterConfig) {
        super(filterConfig);
    }

    @Override
    protected String[] splitChainDefinition(String chainDefinition) {
        return super.splitChainDefinition("ef, " + chainDefinition);
    }
}
