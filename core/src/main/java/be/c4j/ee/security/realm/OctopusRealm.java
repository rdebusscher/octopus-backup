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

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.config.OctopusConfig;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.permission.OctopusPermissionResolver;
import be.c4j.ee.security.salt.HashEncoding;
import be.c4j.ee.security.systemaccount.SystemAccountAuthenticationToken;
import be.c4j.ee.security.token.IncorrectDataToken;
import be.c4j.ee.security.twostep.TwoStepAuthenticationInfo;
import be.c4j.ee.security.twostep.TwoStepConfig;
import be.c4j.ee.security.util.CodecUtil;
import org.apache.deltaspike.core.api.provider.BeanProvider;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.CredentialsException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ThreadContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class OctopusRealm extends AuthorizingRealm {

    private static final Logger log = LoggerFactory.getLogger(OctopusRealm.class);

    public static final String IN_AUTHENTICATION_FLAG = "InAuthentication";
    public static final String IN_AUTHORIZATION_FLAG = "InAuthorization";
    public static final String SYSTEM_ACCOUNT_AUTHENTICATION = "SystemAccountAuthentication";

    private SecurityDataProvider securityDataProvider;

    private OctopusConfig config;

    private List<OctopusDefinedAuthenticationInfo> octopusDefinedAuthenticationInfoList;
    private List<OctopusDefinedAuthorizationInfo> octopusDefinedAuthorizationInfoList;

    private TwoStepConfig twoStepConfig;

    private CodecUtil codecUtil;

    @Override
    protected void onInit() {
        super.onInit();
        securityDataProvider = BeanProvider.getContextualReference(SecurityDataProvider.class);
        config = BeanProvider.getContextualReference(OctopusConfig.class);
        twoStepConfig = BeanProvider.getContextualReference(TwoStepConfig.class);
        codecUtil = BeanProvider.getContextualReference(CodecUtil.class);

        octopusDefinedAuthenticationInfoList = BeanProvider.getContextualReferences(OctopusDefinedAuthenticationInfo.class, false);
        octopusDefinedAuthorizationInfoList = BeanProvider.getContextualReferences(OctopusDefinedAuthorizationInfo.class, false);

        setCachingEnabled(true);
        setAuthenticationTokenClass(AuthenticationToken.class);
        setPermissionResolver(BeanProvider.getContextualReference(OctopusPermissionResolver.class));
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        ThreadContext.put(IN_AUTHORIZATION_FLAG, new InAuthorization());

        AuthorizationInfo authorizationInfo = null;
        try {

            Iterator<OctopusDefinedAuthorizationInfo> iterator = octopusDefinedAuthorizationInfoList.iterator();
            Object primaryPrincipal = principals.getPrimaryPrincipal();
            while (authorizationInfo == null && iterator.hasNext()) {
                authorizationInfo = iterator.next().getAuthorizationInfo(primaryPrincipal);
            }

            if (authorizationInfo == null) {

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

        // TODO What about IncorrectDataToken, should be return null immediatly??
        // How is IncorrectDataToken used?
        Iterator<OctopusDefinedAuthenticationInfo> iterator = octopusDefinedAuthenticationInfoList.iterator();
        while (authenticationInfo == null && iterator.hasNext()) {
            authenticationInfo = iterator.next().getAuthenticationInfo(token);
        }

        if (authenticationInfo == null && !(token instanceof IncorrectDataToken)) {
            ThreadContext.put(IN_AUTHENTICATION_FLAG, new InAuthentication());
            try {
                authenticationInfo = securityDataProvider.getAuthenticationInfo(token);

                verifyHashEncoding(authenticationInfo);
            } finally {
                // Even in the case of an exception (access not allowed) we need to reset this flag
                ThreadContext.remove(IN_AUTHENTICATION_FLAG);
            }

        }

        if (authenticationInfo != null && authenticationInfo.getPrincipals() != null) {
            Object principal = authenticationInfo.getPrincipals().getPrimaryPrincipal();
            if (principal instanceof UserPrincipal) {
                UserPrincipal user = (UserPrincipal) principal;
                user.addUserInfo(OctopusConstants.TOKEN, token);
            }
        }

        return authenticationInfo;
    }

    private void verifyHashEncoding(AuthenticationInfo info) {
        if (!config.getHashAlgorithmName().isEmpty() && info != null) {
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
        super.assertCredentialsMatch(token, info);

        defineTwoStepAuthentication(info);
    }

    private void defineTwoStepAuthentication(AuthenticationInfo info) {
        if (info instanceof TwoStepAuthenticationInfo) {
            return;
        }
        Object principal = info.getPrincipals().getPrimaryPrincipal();
        if (principal instanceof UserPrincipal) {
            UserPrincipal userPrincipal = (UserPrincipal) principal;
            if (twoStepConfig.getAlwaysTwoStepAuthentication() != null) {
                if (twoStepConfig.getAlwaysTwoStepAuthentication()) {
                    userPrincipal.setNeedsTwoStepAuthentication(true);
                }
            }
        }
    }

    public Collection<Permission> getPermissions(PrincipalCollection principal) {
        AuthorizationInfo info = getAuthorizationInfo(principal);
        return getPermissions(info);
    }

    public void setAuthorizationCachedData(UserPrincipal userPrincipal, AuthorizationInfo authorizationInfo) {
        Cache<Object, AuthorizationInfo> cache = getAuthorizationCache();
        if (cache == null && isAuthorizationCachingEnabled() && authorizationInfo != null) {
            cache = createAuthorizationCache();

        }
        if (cache != null) {
            if (authorizationInfo != null) {
                // If we have a cache at this moment, store the data in the cache.
                cache.put(userPrincipal, authorizationInfo);
            } else {
                cache.remove(userPrincipal);
            }
        }
    }

    private Cache<Object, AuthorizationInfo> createAuthorizationCache() {

        if (getAuthorizationCache() == null) {
            // Check to be on the safe side :)

            if (log.isDebugEnabled()) {
                log.debug("No authorizationCache instance set.  Checking for a cacheManager...");
            }

            CacheManager cacheManager = getCacheManager();

            if (cacheManager != null) {
                String cacheName = getAuthorizationCacheName();
                if (log.isDebugEnabled()) {
                    log.debug("CacheManager [" + cacheManager + "] has been configured.  Building " +
                            "authorization cache named [" + cacheName + "]");
                }
                setAuthorizationCache(cacheManager.<Object, AuthorizationInfo>getCache(cacheName));
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("No cache or cacheManager properties have been set.  Authorization cache cannot " +
                            "be obtained.");
                }
            }
        }

        return getAuthorizationCache();
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
