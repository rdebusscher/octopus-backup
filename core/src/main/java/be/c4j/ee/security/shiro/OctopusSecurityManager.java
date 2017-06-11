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
import be.c4j.ee.security.event.RememberMeLogonEvent;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.realm.OctopusRealm;
import be.c4j.ee.security.sso.SSOPrincipalProvider;
import be.c4j.ee.security.twostep.TwoStepAuthenticationInfo;
import be.c4j.ee.security.twostep.TwoStepSubject;
import org.apache.deltaspike.core.api.provider.BeanManagerProvider;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.subject.MutablePrincipalCollection;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static be.c4j.ee.security.realm.AuthenticationInfoBuilder.DEFAULT_REALM;

/**
 *
 */
public class OctopusSecurityManager extends DefaultWebSecurityManager {

    private static final Logger log = LoggerFactory.getLogger(OctopusSecurityManager.class);

    private SubjectFactory twoStepSubjectFactory;

    private SSOPrincipalProvider ssoPrincipalProvider;

    private OctopusRealm octopusRealm;

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
            // If we have TwoStepAuthenticationInfo, we have fisnished the second step of the authentication.
            UserPrincipal userPrincipal = (UserPrincipal) subject.getPrincipal();
            userPrincipal.setNeedsTwoStepAuthentication(false);

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

        PrincipalCollection principals = context.resolvePrincipals();

        UserPrincipal userPrincipal = getUserPrincipal(principals);

        Subject result;
        if (userPrincipal == null) {
            result = getSubjectFactory().createSubject(context);
        } else {
            // FIXME the different realm names isn't solved yet :)
            if (principals instanceof MutablePrincipalCollection && ssoPrincipalProvider != null) {
                ((MutablePrincipalCollection) principals).add(ssoPrincipalProvider.createSSOPrincipal(userPrincipal), DEFAULT_REALM);
            }

            if (userPrincipal.needsTwoStepAuthentication()) {

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

    @Override
    protected void onFailedLogin(AuthenticationToken token, AuthenticationException ae, Subject subject) {
        super.onFailedLogin(token, ae, subject);  // Do the default stuff (with the rememberme manager
        if (subject instanceof TwoStepSubject) {
            // There is a failure in the validation of the OTP token
            // log the user out since authentication as a whole failed.
            subject.logout();
        }
    }

    @Override
    protected void save(Subject subject) {
        super.save(subject);
        if (subject.isRemembered()) {
            // Ok, now the DAO has stored the Subject in the Session and thus HttpSession is created.
            // We now can sent an event (required for example for the ApplicationUsage) that there is a RememberedLogon.

            BeanManagerProvider.getInstance().getBeanManager().fireEvent(new RememberMeLogonEvent(subject));
        }

    }

    @Override
    protected void afterRealmsSet() {
        super.afterRealmsSet();
        octopusRealm = (OctopusRealm) getRealms().iterator().next();  // We use always only 1 realm, OctopusRealm
    }

    public Collection<Permission> getPermissions(Subject subject, Permission permission) {
        // FIXME Need some cache !!!
        Collection<Permission> result = new ArrayList<Permission>();

        Collection<Permission> permissions = octopusRealm.getPermissions(subject.getPrincipals());
        for (Permission currentPermission : permissions) {
            if (currentPermission.implies(permission)) {
                result.add(currentPermission);
            }
        }
        return result;
    }
}
