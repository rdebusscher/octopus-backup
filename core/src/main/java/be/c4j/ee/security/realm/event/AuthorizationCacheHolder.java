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
package be.c4j.ee.security.realm.event;

import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import java.util.Collection;

/**
 *
 */
@ApplicationScoped
public class AuthorizationCacheHolder {

    private Cache<Object, AuthorizationInfo> cache;

    public void clearCache(@Observes ClearAuthorizationCacheEvent event) {
        checkCache();
        if (cache != null) {
            UserPrincipal userPrincipal = event.getUserPrincipal();
            if (userPrincipal == null) {
                // no principal specified in event, clear all
                cache.clear();
            } else {
                // remove only for one principal
                // cache.remove(userPrincipal); -> doesn't when we have a CDI proxy for userPrincipal

                Object key = null;
                for (Object k : cache.keys()) {
                    if (k.equals(userPrincipal)) {
                        key = k;
                    }
                }

                if (key != null) {
                    cache.remove(key);
                }

            }
        }
    }

    private void checkCache() {
        if (cache == null) {
            SecurityManager securityManager = SecurityUtils.getSecurityManager();
            if (securityManager instanceof RealmSecurityManager) {
                RealmSecurityManager realmSecurityManager = (RealmSecurityManager) securityManager;
                AuthorizingRealm realm = findCorrectRealm(realmSecurityManager.getRealms());
                if (realm != null) {
                    cache = realm.getAuthorizationCache();
                }
            }
        }

    }

    private AuthorizingRealm findCorrectRealm(Collection<Realm> realms) {
        AuthorizingRealm result = null;
        for (Realm realm : realms) {
            if (realm instanceof AuthorizingRealm) {
                result = (AuthorizingRealm) realm;
            }
        }
        return result;
    }
}
