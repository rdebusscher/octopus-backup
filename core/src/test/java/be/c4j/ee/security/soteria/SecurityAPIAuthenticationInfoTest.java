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
package be.c4j.ee.security.soteria;

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.model.UserPrincipal;
import org.apache.shiro.subject.PrincipalCollection;
import org.junit.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class SecurityAPIAuthenticationInfoTest {

    @Test
    public void getPrincipals() {
        // See if callerGroups are available under userInfo with key OctopusConstants.CALLER_GROUPS

        String uniqueId = "X";
        String name = "JUnit";
        Set<String> callerGroups = new HashSet<String>();
        callerGroups.add("group1");
        callerGroups.add("group2");

        SecurityAPIAuthenticationInfo securityAPIAuthenticationInfo = new SecurityAPIAuthenticationInfo(uniqueId, name, callerGroups);

        PrincipalCollection principals = securityAPIAuthenticationInfo.getPrincipals();

        assertThat(principals.getPrimaryPrincipal()).isExactlyInstanceOf(UserPrincipal.class);

        UserPrincipal userPrincipal = (UserPrincipal) principals.getPrimaryPrincipal();

        List<String> groups = userPrincipal.getUserInfo(OctopusConstants.CALLER_GROUPS);
        assertThat(groups).containsOnly("group1", "group2");
    }

}