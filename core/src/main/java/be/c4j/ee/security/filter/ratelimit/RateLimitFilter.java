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
package be.c4j.ee.security.filter.ratelimit;

import be.c4j.ee.security.exception.OctopusConfigurationException;
import org.apache.shiro.ShiroException;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.PathMatchingFilter;

import javax.servlet.Filter;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

import static be.c4j.ee.security.filter.shiro.OctopusPathMatchingFilterChainResolver.OCTOPUS_CHAIN_NAME;

/**
 *
 */
public class RateLimitFilter extends PathMatchingFilter implements Initializable {

    private RateLimitConfig rateLimitConfig;

    private Map<String, FixedBucket> rateLimiters;

    @Override
    public void init() throws ShiroException {
        rateLimitConfig = new RateLimitConfig();
        rateLimiters = new HashMap<String, FixedBucket>();
    }

    @Override
    public Filter processPathConfig(String path, String config) {
        Filter result = super.processPathConfig(path, config);
        String[] configValues = (String[]) appliedPaths.get(path);

        if (configValues.length != 1) {
            throw new OctopusConfigurationException(String.format("Configuration of Rate limit filter on path %s is wrong (%s)", path, config));
        }
        rateLimiters.put(path, rateLimitConfig.createRateLimiter(configValues[0]));
        return result;
    }

    @Override
    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {

        String path = (String) request.getAttribute(OCTOPUS_CHAIN_NAME);
        Token token = rateLimiters.get(path).getToken(path);  // key should be some x-api-key header stuff for REST??
        if (!token.isUsable()) {
            HttpServletResponse httpServletResponse = (HttpServletResponse) response;
            httpServletResponse.setStatus(429);  //Too many requests
            httpServletResponse.setContentType("text/plain");
            httpServletResponse.getWriter().write("Rate limit exceeded");
        }
        return token.isUsable();
    }

}
