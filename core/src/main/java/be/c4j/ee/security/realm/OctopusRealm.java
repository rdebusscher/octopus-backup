/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
package be.c4j.ee.security.realm;

import be.c4j.ee.security.context.OctopusSecurityContext;
import be.c4j.ee.security.systemaccount.SystemAccountAuthenticationToken;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ThreadContext;

public class OctopusRealm extends AuthorizingRealm {

    public static final String IN_AUTHENTICATION_FLAG = "InAuthentication";
    public static final String IN_AUTHORIZATION_FLAG = "InAuthorization";

    private SecurityDataProvider securityDataProvider;

    @Override
    protected void onInit() {
        super.onInit();
        securityDataProvider = BeanProvider.getContextualReference(SecurityDataProvider.class);
        setCachingEnabled(true);
        setAuthenticationTokenClass(AuthenticationToken.class);
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        ThreadContext.put(IN_AUTHORIZATION_FLAG, new InAuthorization());
        AuthorizationInfo authorizationInfo;
        try {
            Object primaryPrincipal = principals.getPrimaryPrincipal();
            if (OctopusSecurityContext.isSystemAccount(primaryPrincipal)) {
                // No permissions or roles, use @SystemAccount
                authorizationInfo = new SimpleAuthorizationInfo();
            } else {
                authorizationInfo = securityDataProvider.getAuthorizationInfo(principals);
            }
        } finally {

            ThreadContext.remove(IN_AUTHORIZATION_FLAG);
        }
        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        ThreadContext.put(IN_AUTHENTICATION_FLAG, new InAuthentication());
        AuthenticationInfo authenticationInfo;
        if (token instanceof SystemAccountAuthenticationToken) {
            // TODO Check about the realm names
            authenticationInfo = new SimpleAuthenticationInfo(token.getPrincipal(), "", AuthenticationInfoBuilder.DEFAULT_REALM);
        } else {
            try {
                authenticationInfo = securityDataProvider.getAuthenticationInfo(token);
            } finally {
                // Even in the case of an exception (access not allowed) we need to reset this flag
                ThreadContext.remove(IN_AUTHENTICATION_FLAG);
            }
        }
        return authenticationInfo;
    }

    protected Object getAuthorizationCacheKey(PrincipalCollection principals) {
        return principals.getPrimaryPrincipal();
    }

    public static class InAuthentication {

        private InAuthentication() {
        }
    }

    public static class InAuthorization {

        private InAuthorization() {
        }
    }
}
