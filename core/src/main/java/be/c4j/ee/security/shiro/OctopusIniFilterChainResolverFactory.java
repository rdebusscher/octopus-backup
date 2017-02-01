package be.c4j.ee.security.shiro;

import be.c4j.ee.security.filter.shiro.OctopusPathMatchingFilterChainResolver;
import org.apache.shiro.config.Ini;
import org.apache.shiro.web.config.IniFilterChainResolverFactory;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;

import javax.servlet.FilterConfig;
import java.util.Map;

/**
 */

public class OctopusIniFilterChainResolverFactory extends IniFilterChainResolverFactory {

    public OctopusIniFilterChainResolverFactory() {
        super();
    }

    public OctopusIniFilterChainResolverFactory(Ini ini) {
        super(ini);
    }

    public OctopusIniFilterChainResolverFactory(Ini ini, Map<String, ?> defaultBeans) {
        super(ini, defaultBeans);
    }

    @Override
    protected FilterChainResolver createDefaultInstance() {
        FilterConfig filterConfig = getFilterConfig();
        if (filterConfig != null) {
            return new OctopusPathMatchingFilterChainResolver(filterConfig);
        } else {
            return new OctopusPathMatchingFilterChainResolver();
        }

    }
}
