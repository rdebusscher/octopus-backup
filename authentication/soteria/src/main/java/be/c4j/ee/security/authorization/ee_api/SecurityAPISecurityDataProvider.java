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
package be.c4j.ee.security.authorization.ee_api;

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.realm.AuthorizationInfoBuilder;
import be.c4j.ee.security.realm.SecurityDataProvider;
import be.c4j.ee.security.role.SimpleNamedRole;
import be.c4j.ee.security.soteria.SecurityAPIAuthenticationInfo;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.credential.Password;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStoreHandler;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class SecurityAPISecurityDataProvider implements SecurityDataProvider {

    @Inject
    private IdentityStoreHandler identityStoreHandler;

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        if (token instanceof UsernamePasswordToken) {
            UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;

            Credential credential = new UsernamePasswordCredential(usernamePasswordToken.getUsername(), new Password(usernamePasswordToken.getPassword()));
            CredentialValidationResult validationResult = identityStoreHandler.validate(credential);

            if (validationResult.getStatus() == CredentialValidationResult.Status.VALID) {
                String callerUniqueId = validationResult.getCallerUniqueId();
                if (callerUniqueId == null) {
                    callerUniqueId = usernamePasswordToken.getUsername();
                }
                return new SecurityAPIAuthenticationInfo(callerUniqueId, validationResult.getCallerPrincipal().getName(), validationResult.getCallerGroups());
            }
        }
        return null;
    }

    @Override
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        UserPrincipal userPrincipal = (UserPrincipal) principals.getPrimaryPrincipal();
        List<String> callerGroups = userPrincipal.getUserInfo(OctopusConstants.CALLER_GROUPS);

        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();
        // Define each 'callerGroup' as permission and as role. The RolePermissionResolver can be used to convert the role to a list of permissions.

        for (String callerGroup : callerGroups) {
            builder.addRole(new SimpleNamedRole(callerGroup));
            builder.addPermission(callerGroup);
        }

        return builder.build();
    }
}
