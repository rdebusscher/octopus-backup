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
package be.c4j.ee.security.sso.client;

import be.c4j.ee.security.PasswordGenerator;
import be.c4j.ee.security.shiro.OctopusUserFilter;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.ShiroException;
import org.apache.shiro.util.Initializable;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 *
 */
public class SSOOctopusUserFilter extends OctopusUserFilter implements Initializable {

    private ThreadLocal<String> stateValue;

    private PasswordGenerator passwordGenerator;

    @Override
    public void init() throws ShiroException {
        passwordGenerator = BeanProvider.getContextualReference(PasswordGenerator.class);
        stateValue = new ThreadLocal<String>();
    }

    @Override
    public String getLoginUrl() {
        String loginURL = super.getLoginUrl();

        String state = stateValue.get();

        return loginURL + "&state=" + state;
    }

    @Override
    public void prepareLoginURL(ServletRequest request, ServletResponse response) {
        // FIXME when we integrate Shiro, update the getLoginURL with parameters so that we can have access to the request
        String state = passwordGenerator.generate(16);

        stateValue.set(state);

        HttpServletRequest httpServletRequest = (HttpServletRequest) request;

        HttpSession session = httpServletRequest.getSession(true);
        session.setAttribute("state", state);

    }

    @Override
    protected void cleanup(ServletRequest request, ServletResponse response, Exception existing) throws ServletException, IOException {
        super.cleanup(request, response, existing);

        stateValue.remove();  // To be on the safe side that the ThreadLocal is cleanup properly.
        // TODO When shiro integrated we probably don't need this anymore as wd don't use the ThreadLocal anymore.
    }
}
