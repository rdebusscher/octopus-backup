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
package be.c4j.demo.security;

import be.c4j.ee.security.realm.AuthenticationInfoBuilder;
import be.c4j.ee.security.realm.SecurityDataProvider;
import be.c4j.ee.security.salt.SaltHashingUtil;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;


@ApplicationScoped
public class AppAuthentication implements SecurityDataProvider {

    private int principalId = 0;

    @Inject
    private SaltHashingUtil saltHashingUtil;

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        if (token instanceof UsernamePasswordToken) {
            UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;

            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
            authenticationInfoBuilder.principalId(principalId++).name(token.getPrincipal().toString());

            // Best practice is that each user has his own salt value. So we create a salt here for each checks to simulate that.
            // See also the saltLength parameter for the length of this salt.
            byte[] salt = saltHashingUtil.nextSalt();

            authenticationInfoBuilder.salt(salt);
            // TODO: Change for production. Here we use username as password
            String hashedPassword = saltHashingUtil.hash(usernamePasswordToken.getUsername(), salt);
            authenticationInfoBuilder.password(hashedPassword);

            return authenticationInfoBuilder.build();
        }
        return null;
    }

    @Override
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        // TODO: Change for production. Principal has no assigned no permission not roles.
        return new SimpleAuthorizationInfo();
    }

}
