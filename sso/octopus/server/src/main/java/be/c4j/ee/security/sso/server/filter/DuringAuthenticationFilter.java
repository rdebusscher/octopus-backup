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
 *
 */
package be.c4j.ee.security.sso.server.filter;

import be.c4j.ee.security.sso.encryption.SSODataEncryptionHandler;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.util.Initializable;
import org.apache.shiro.web.filter.PathMatchingFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
public class DuringAuthenticationFilter extends PathMatchingFilter implements Initializable {

    private SSODataEncryptionHandler encryptionHandler;

    @Override
    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {

        return encryptionHandler.validate((HttpServletRequest) request);
    }

    @Override
    public void init() throws ShiroException {
        // Here required. Because when we use this filter we want to check the encryption :)
        encryptionHandler = BeanProvider.getContextualReference(SSODataEncryptionHandler.class);
    }
}
