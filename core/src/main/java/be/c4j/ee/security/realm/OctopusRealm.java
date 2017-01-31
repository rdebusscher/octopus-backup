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
package be.c4j.ee.security.realm;

import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.context.OctopusSecurityContext;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.OctopusPermissionResolver;
import be.c4j.ee.security.salt.HashEncoding;
import be.c4j.ee.security.systemaccount.SystemAccountAuthenticationToken;
import be.c4j.ee.security.token.IncorrectDataToken;
import be.c4j.ee.security.twostep.TwoStepAuthenticationInfo;
import be.c4j.ee.security.twostep.TwoStepConfig;
import be.c4j.ee.security.twostep.TwoStepProvider;
import be.c4j.ee.security.util.CodecUtil;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ThreadContext;

public class OctopusRealm extends AuthorizingRealm {

    public static final String IN_AUTHENTICATION_FLAG = "InAuthentication";
    public static final String IN_AUTHORIZATION_FLAG = "InAuthorization";
    public static final String SYSTEM_ACCOUNT_AUTHENTICATION = "SystemAccountAuthentication";

    private SecurityDataProvider securityDataProvider;

    private OctopusConfig config;

    private TwoStepConfig twoStepConfig;

    private CodecUtil codecUtil;

    @Override
    protected void onInit() {
        super.onInit();
        securityDataProvider = BeanProvider.getContextualReference(SecurityDataProvider.class);
        config = BeanProvider.getContextualReference(OctopusConfig.class);
        twoStepConfig = BeanProvider.getContextualReference(TwoStepConfig.class);
        codecUtil = BeanProvider.getContextualReference(CodecUtil.class);

        setCachingEnabled(true);
        setAuthenticationTokenClass(AuthenticationToken.class);
        setPermissionResolver(BeanProvider.getContextualReference(OctopusPermissionResolver.class));
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
        AuthenticationInfo authenticationInfo = null;
        if (token instanceof SystemAccountAuthenticationToken) {
            // TODO Check about the realm names
            authenticationInfo = new SimpleAuthenticationInfo(token.getPrincipal(), "", AuthenticationInfoBuilder.DEFAULT_REALM);
        }
        if (authenticationInfo == null && twoStepConfig.getTwoStepAuthenticationActive()) {
            UserPrincipal userPrincipal = (UserPrincipal) SecurityUtils.getSubject().getPrincipal();
            if (userPrincipal != null && userPrincipal.needsTwoStepAuthentication()) {
                // When we are performing validation of the second step, we have already a Principal (unauthenticated)
                TwoStepProvider twoStepProvider = BeanProvider.getContextualReference(TwoStepProvider.class);
                authenticationInfo = twoStepProvider.defineAuthenticationInfo(token, userPrincipal);
            }
        }
        if (authenticationInfo == null && !(token instanceof IncorrectDataToken)) {
            ThreadContext.put(IN_AUTHENTICATION_FLAG, new InAuthentication());
            try {
                authenticationInfo = securityDataProvider.getAuthenticationInfo(token);
                // TODO Document this action
                if (authenticationInfo != null) {
                    UserPrincipal user = (UserPrincipal) authenticationInfo.getPrincipals().getPrimaryPrincipal();
                    user.addUserInfo("token", token);  // TODO Create constants!!
                }

                verifyHashEncoding(authenticationInfo);
            } finally {
                // Even in the case of an exception (access not allowed) we need to reset this flag
                ThreadContext.remove(IN_AUTHENTICATION_FLAG);
            }

        }
        return authenticationInfo;
    }

    private void verifyHashEncoding(AuthenticationInfo info) {
        if (!config.getHashAlgorithmName().isEmpty()) {
            Object credentials = info.getCredentials();

            if (credentials instanceof String || credentials instanceof char[]) {

                byte[] storedBytes = codecUtil.toBytes(credentials);
                HashEncoding hashEncoding = config.getHashEncoding();

                try {
                    // Lets try to decode, if we have an issue the supplied hash password is invalid.
                    switch (hashEncoding) {

                        case HEX:
                            Hex.decode(storedBytes);
                            break;
                        case BASE64:
                            Base64.decode(storedBytes);
                            break;
                        default:
                            throw new IllegalArgumentException("hashEncoding " + hashEncoding + " not supported");

                    }
                } catch (IllegalArgumentException e) {
                    throw new CredentialsException("Supplied hashed password can't be decoded. Is the 'hashEncoding' correctly set?");
                }
            }

        }
    }

    protected Object getAuthorizationCacheKey(PrincipalCollection principals) {
        return principals.getPrimaryPrincipal();
    }

    protected boolean isAuthenticationCachingEnabled(AuthenticationToken token, AuthenticationInfo info) {
        boolean result = false;  // For systemAccounts, no caching
        if (!(token instanceof SystemAccountAuthenticationToken)) {
            result = isAuthenticationCachingEnabled();
        }
        return result;
    }

    @Override
    protected void assertCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) throws AuthenticationException {
        ThreadContext.put(SYSTEM_ACCOUNT_AUTHENTICATION, new InSystemAccountAuthentication());
        try {
            super.assertCredentialsMatch(token, info);

            defineTwoStepAuthentication(info);
        } finally {
            ThreadContext.remove(SYSTEM_ACCOUNT_AUTHENTICATION);
        }
    }

    private void defineTwoStepAuthentication(AuthenticationInfo info) {
        if (info instanceof TwoStepAuthenticationInfo) {
            return;
        }
        UserPrincipal userPrincipal = (UserPrincipal) info.getPrincipals().getPrimaryPrincipal();
        if (twoStepConfig.getAlwaysTwoStepAuthentication() != null) {
            if (twoStepConfig.getAlwaysTwoStepAuthentication()) {
                userPrincipal.setNeedsTwoStepAuthentication(true);
            }
        }
    }

    public static class InAuthentication {

        private InAuthentication() {
        }
    }

    public static class InAuthorization {

        private InAuthorization() {
        }
    }

    public static final class InSystemAccountAuthentication {
        // So that we only can create this class from this class.
        private InSystemAccountAuthentication() {
        }
    }

}
