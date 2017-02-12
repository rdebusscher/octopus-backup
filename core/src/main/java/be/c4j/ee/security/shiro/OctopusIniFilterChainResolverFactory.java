/*
 * Copyright 2014-2017 Rudy De Busscher (www.c4j.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
