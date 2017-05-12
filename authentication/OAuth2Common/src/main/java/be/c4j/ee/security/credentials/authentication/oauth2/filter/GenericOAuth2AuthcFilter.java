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

import static be.c4j.ee.security.OctopusConstants.BEARER;

/**
 *
 */
public class GenericOAuth2AuthcFilter extends BasicHttpAuthenticationFilter implements Initializable {

    public static final String OAUTH2_PROVIDER = "provider";

    private OAuth2AuthcFilterManager filterManager;

    public GenericOAuth2AuthcFilter() {
        setAuthcScheme("Multiple provider OAuth2");
        setAuthzScheme(BEARER);
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