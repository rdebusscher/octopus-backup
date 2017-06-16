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
package be.c4j.demo.security;

import be.c4j.demo.security.custom.MyCheckInfo;
import be.c4j.demo.security.custom.SpecialNamedPermission;
import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.realm.AuthenticationInfoBuilder;
import be.c4j.ee.security.realm.AuthorizationInfoBuilder;
import be.c4j.ee.security.realm.SecurityDataProvider;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;

import javax.enterprise.context.ApplicationScoped;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@ApplicationScoped
public class AppAuthentication implements SecurityDataProvider {

    private int principalId = 0;

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        if (token instanceof UsernamePasswordToken) {
            UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;

            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
            authenticationInfoBuilder.principalId(principalId++).name(token.getPrincipal().toString());
            authenticationInfoBuilder.userName(token.getPrincipal().toString());
            // TODO: Change for production. Here we use username as password
            authenticationInfoBuilder.password(usernamePasswordToken.getUsername());

            return authenticationInfoBuilder.build();
        }
        return null;
    }


    @Override
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        AuthorizationInfoBuilder authorizationInfoBuilder = new AuthorizationInfoBuilder();

        List<Long> partitionList1 = definePartitionList(1L);
        List<Long> partitionList2 = definePartitionList(2L);
        List<Long> partitionList3 = definePartitionList(1L, 2L);
        UserPrincipal userPrincipal = (UserPrincipal) principals.getPrimaryPrincipal();

        boolean permissionsAdded = false;
        String userName = userPrincipal.getUserName();
        if ("admin".equals(userName)) {
            authorizationInfoBuilder.addPermission(new SpecialNamedPermission("demo", "demo:*:*", MyCheckInfo.BASIC, partitionList3));
            permissionsAdded = true;
        }
        if ("rudy".equals(userName)) {
            authorizationInfoBuilder.addPermission(new SpecialNamedPermission("demo", "demo:*:*", MyCheckInfo.EXTENDED, null));
            permissionsAdded = true;
        }
        if (!permissionsAdded) {
            if (userName.length() % 2 == 0) {
                authorizationInfoBuilder.addPermission(new SpecialNamedPermission("demo", "demo:*:*", MyCheckInfo.BASIC, partitionList2));

            } else {
                authorizationInfoBuilder.addPermission(new SpecialNamedPermission("demo", "demo:*:*", MyCheckInfo.BASIC, partitionList1));

            }
        }
        return authorizationInfoBuilder.build();
    }

    private List<Long> definePartitionList(Long... ids) {
        List<Long> result = new ArrayList<Long>();
        Collections.addAll(result, ids);
        return result;
    }

}
