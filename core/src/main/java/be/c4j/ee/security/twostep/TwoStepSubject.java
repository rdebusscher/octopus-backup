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
package be.c4j.ee.security.twostep;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.web.subject.support.WebDelegatingSubject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 *
 */
public class TwoStepSubject extends WebDelegatingSubject {
    public TwoStepSubject(PrincipalCollection principals, String host, Session session, ServletRequest request, ServletResponse response, SecurityManager securityManager) {
        super(principals, false, host, session, request, response, securityManager);
    }

    public TwoStepSubject(PrincipalCollection principals, String host, Session session, boolean sessionEnabled, ServletRequest request, ServletResponse response, SecurityManager securityManager) {
        super(principals, false, host, session, sessionEnabled, request, response, securityManager);
    }
}
