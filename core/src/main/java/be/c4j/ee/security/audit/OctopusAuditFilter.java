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
package be.c4j.ee.security.audit;

import org.apache.deltaspike.core.api.provider.BeanManagerProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.web.filter.PathMatchingFilter;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

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

            String userAgent = ((HttpServletRequest)request).getHeader("User-Agent");
            BeanManagerProvider.getInstance().getBeanManager().fireEvent(new OctopusAuditEvent(requestURI, principal, remoteAddress, userAgent));
        }


        return true;
    }
}
