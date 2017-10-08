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
import be.c4j.ee.security.role.NamedApplicationRole;
import be.c4j.ee.security.soteria.SecurityAPIAuthenticationInfo;
import be.c4j.test.util.BeanManagerFake;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.security.enterprise.CallerPrincipal;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStoreHandler;
import java.util.*;

import static be.c4j.ee.security.realm.AuthenticationInfoBuilder.DEFAULT_REALM;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 *
 */
// .Silent so that no Exception is thrown due to unnessecary stubbing. This is within BeanManagerFake,
// but we need it due to some manual lookup in CDI of optional beans.
@RunWith(MockitoJUnitRunner.Silent.class)
public class SecurityAPISecurityDataProviderTest {

    private static final String USER_NAME = "JUnit";
    private static final char[] PASSWORD = "TopSecret".toCharArray();
    private static final String UNIQUE_ID = "Unique";
    private static final String CALLER_NAME = "callerName";

    @Mock
    private IdentityStoreHandler identityStoreHandlerMock;

    @InjectMocks
    private SecurityAPISecurityDataProvider dataProvider;

    @Captor
    private ArgumentCaptor<Credential> credentialCapture;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();
        beanManagerFake.endRegistration(); // required for the getAuthorizationInfo test method.
    }

    @Test
    public void getAuthenticationInfo_valid_uniqueId() {

        AuthenticationToken usernamePassword = new UsernamePasswordToken(USER_NAME, PASSWORD);

        Set<String> groups = new HashSet<String>();
        groups.add("group1");
        groups.add("group2");

        CallerPrincipal callerPrincipal = new CallerPrincipal(CALLER_NAME);
        CredentialValidationResult validationResult = new CredentialValidationResult(null, callerPrincipal, null, UNIQUE_ID, groups);
        when(identityStoreHandlerMock.validate(credentialCapture.capture())).thenReturn(validationResult);

        AuthenticationInfo authenticationInfo = dataProvider.getAuthenticationInfo(usernamePassword);
        assertThat(authenticationInfo).isNotNull();

        assertThat(authenticationInfo).isInstanceOf(SecurityAPIAuthenticationInfo.class);

        SecurityAPIAuthenticationInfo info = (SecurityAPIAuthenticationInfo) authenticationInfo;
        UserPrincipal userPrincipal = (UserPrincipal) info.getPrincipals().getPrimaryPrincipal();

        assertThat(userPrincipal.getId()).isEqualTo(UNIQUE_ID);
        List<String> groupsPrincipal = userPrincipal.getUserInfo(OctopusConstants.CALLER_GROUPS);
        assertThat(groupsPrincipal).containsOnly("group1", "group2");

        Credential credential = credentialCapture.getValue();
        assertThat(credential).isExactlyInstanceOf(UsernamePasswordCredential.class);

        UsernamePasswordCredential usernamePasswordCredential = (UsernamePasswordCredential) credential;
        assertThat(usernamePasswordCredential.getCaller()).isEqualTo(USER_NAME);
        assertThat(usernamePasswordCredential.getPasswordAsString()).isEqualTo("TopSecret");
    }

    @Test
    public void getAuthenticationInfo_valid_noUniqueId() {

        AuthenticationToken usernamePassword = new UsernamePasswordToken(USER_NAME, PASSWORD);

        Set<String> groups = new HashSet<String>();
        groups.add("group1");
        groups.add("group2");

        CallerPrincipal callerPrincipal = new CallerPrincipal(CALLER_NAME);
        CredentialValidationResult validationResult = new CredentialValidationResult(null, callerPrincipal, null, null, groups);
        when(identityStoreHandlerMock.validate(credentialCapture.capture())).thenReturn(validationResult);

        AuthenticationInfo authenticationInfo = dataProvider.getAuthenticationInfo(usernamePassword);
        assertThat(authenticationInfo).isNotNull();

        assertThat(authenticationInfo).isInstanceOf(SecurityAPIAuthenticationInfo.class);

        SecurityAPIAuthenticationInfo info = (SecurityAPIAuthenticationInfo) authenticationInfo;
        UserPrincipal userPrincipal = (UserPrincipal) info.getPrincipals().getPrimaryPrincipal();

        assertThat(userPrincipal.getId()).isEqualTo(USER_NAME);
        List<String> groupsPrincipal = userPrincipal.getUserInfo(OctopusConstants.CALLER_GROUPS);
        assertThat(groupsPrincipal).containsOnly("group1", "group2");

        Credential credential = credentialCapture.getValue();
        assertThat(credential).isExactlyInstanceOf(UsernamePasswordCredential.class);

        UsernamePasswordCredential usernamePasswordCredential = (UsernamePasswordCredential) credential;
        assertThat(usernamePasswordCredential.getCaller()).isEqualTo(USER_NAME);
        assertThat(usernamePasswordCredential.getPasswordAsString()).isEqualTo("TopSecret");
    }

    @Test
    public void getAuthenticationInfo_invalid() {

        AuthenticationToken usernamePassword = new UsernamePasswordToken(USER_NAME, PASSWORD);

        when(identityStoreHandlerMock.validate(any(Credential.class))).thenReturn(CredentialValidationResult.INVALID_RESULT);

        AuthenticationInfo authenticationInfo = dataProvider.getAuthenticationInfo(usernamePassword);
        assertThat(authenticationInfo).isNull();

    }

    @Test
    public void getAuthorizationInfo() {

        UserPrincipal userPrincipal = new UserPrincipal(UNIQUE_ID);

        ArrayList<String> callerGroups = new ArrayList<String>();
        // We use Implementation and not interface because we need to have something Serializable!
        callerGroups.add("permission");
        callerGroups.add("role");
        userPrincipal.addUserInfo(OctopusConstants.CALLER_GROUPS, callerGroups);

        PrincipalCollection principals = new SimplePrincipalCollection(userPrincipal, DEFAULT_REALM);

        AuthorizationInfo info = dataProvider.getAuthorizationInfo(principals);

        // Check to see if callerGroups are passed to the String permissions and roles.
        assertThat(info.getStringPermissions()).containsOnlyOnce("permission", "role");

        Collection<Permission> objectPermissions = info.getObjectPermissions();
        assertThat(objectPermissions.iterator().next()).isInstanceOf(NamedApplicationRole.class);
        assertThat(objectPermissions).extracting("roleName").containsOnlyOnce("permission", "role");
    }

}