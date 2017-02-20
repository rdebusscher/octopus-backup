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

import be.c4j.ee.security.access.AfterSuccessfulLoginHandler;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.sso.SSOPrincipalProvider;
import be.c4j.ee.security.twostep.TwoStepAuthenticationInfo;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.subject.MutablePrincipalCollection;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static be.c4j.ee.security.realm.AuthenticationInfoBuilder.DEFAULT_REALM;

/**
 *
 */
public class OctopusSecurityManager extends DefaultWebSecurityManager {

    private static final Logger log = LoggerFactory.getLogger(OctopusSecurityManager.class);

    private SubjectFactory twoStepSubjectFactory;

    private SSOPrincipalProvider ssoPrincipalProvider;

    public OctopusSecurityManager() {
        twoStepSubjectFactory = new TwoStepSubjectFactory();
        setSubjectFactory(new OctopusSubjectFactory());

        ssoPrincipalProvider = BeanProvider.getContextualReference(SSOPrincipalProvider.class, true);
    }

    public Subject login(Subject subject, AuthenticationToken token) throws AuthenticationException {
        AuthenticationInfo info;
        try {
            info = authenticate(token);

        } catch (AuthenticationException ae) {
            try {
                onFailedLogin(token, ae, subject);
            } catch (Exception e) {
                if (log.isInfoEnabled()) {
                    log.info("onFailedLogin method threw an " +
                            "exception.  Logging and propagating original AuthenticationException.", e);
                }
            }
            throw ae; //propagate
        }

        Subject loggedIn;
        if (info instanceof TwoStepAuthenticationInfo) {
            loggedIn = createSubject(token, info, subject);

            onSuccessfulLogin(token, info, loggedIn);

        } else {
            Object principal = info.getPrincipals().getPrimaryPrincipal();
            if (principal instanceof UserPrincipal) {

                UserPrincipal userPrincipal = (UserPrincipal) principal;

                // TODO Review this, Can it be solved differently?
                if (userPrincipal.needsTwoStepAuthentication()) {
                    loggedIn = createTwoStepSubject(token, info, subject);

                } else {
                    loggedIn = createSubject(token, info, subject);

                    onSuccessfulLogin(token, info, loggedIn);

                }
            } else {
                loggedIn = createSubject(token, info, subject);

                onSuccessfulLogin(token, info, loggedIn);

            }
        }
        return loggedIn;
    }

    protected Subject createTwoStepSubject(AuthenticationToken token, AuthenticationInfo info, Subject existing) {
        SubjectContext context = createSubjectContext();
        context.setAuthenticationToken(token);
        context.setAuthenticationInfo(info);
        if (existing != null) {
            context.setSubject(existing);
        }
        return createSubject(context);
    }

    protected Subject doCreateSubject(SubjectContext context) {

        PrincipalCollection principals = getPrincipalCollection(context);

        UserPrincipal userPrincipal = getUserPrincipal(principals);

        Subject result;
        if (userPrincipal == null) {
            result = getSubjectFactory().createSubject(context);
        } else {
            // FIXME the different realm names isn't solved yet :)
            if (principals instanceof MutablePrincipalCollection && ssoPrincipalProvider != null) {
                ((MutablePrincipalCollection) principals).add(ssoPrincipalProvider.createSSOPrincipal(userPrincipal), DEFAULT_REALM);
            }

            if (userPrincipal != null && userPrincipal.needsTwoStepAuthentication()) {

                result = twoStepSubjectFactory.createSubject(context);
            } else {

                result = getSubjectFactory().createSubject(context);
            }
        }
        return result;
    }

    private UserPrincipal getUserPrincipal(PrincipalCollection principals) {
        return principals == null || !(principals.getPrimaryPrincipal() instanceof UserPrincipal) ? null : (UserPrincipal) principals.getPrimaryPrincipal();
    }

    private PrincipalCollection getPrincipalCollection(SubjectContext context) {
        PrincipalCollection result = null;
        AuthenticationInfo authenticationInfo = context.getAuthenticationInfo();
        if (authenticationInfo != null) {
            result = authenticationInfo.getPrincipals();
        }
        return result;
    }

    @Override
    protected void onSuccessfulLogin(AuthenticationToken token, AuthenticationInfo info, Subject subject) {
        List<AfterSuccessfulLoginHandler> handlers = BeanProvider.getContextualReferences(AfterSuccessfulLoginHandler.class, true);
        for (AfterSuccessfulLoginHandler handler : handlers) {
            handler.onSuccessfulLogin(token, info, subject);
        }
        super.onSuccessfulLogin(token, info, subject); // FIXME Convert the rememberMe to AfterSuccessfulLoginHandler

    }
}
