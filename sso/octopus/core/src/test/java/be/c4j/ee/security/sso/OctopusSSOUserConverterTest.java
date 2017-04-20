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
package be.c4j.ee.security.sso;

import be.c4j.ee.security.model.UserPrincipal;
import be.c4j.ee.security.sso.rest.PrincipalUserInfoJSONProvider;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_INFO;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class OctopusSSOUserConverterTest {

    @Mock
    private PrincipalUserInfoJSONProvider jsonProviderMock;

    @InjectMocks
    private OctopusSSOUserConverter octopusSSOUserConverter;

    @Test
    public void asClaims() {
        OctopusSSOUser ssoUser = new OctopusSSOUser();

        ssoUser.setId("IdValue");
        ssoUser.setLocalId("LocalIdValue");

        ssoUser.setUserName("UserNameValue");

        ssoUser.setLastName("LastNameValue");
        ssoUser.setFirstName("FirstNameValue");
        ssoUser.setFullName("FullNameValue");
        ssoUser.setEmail("EmailValue");

        ssoUser.addUserInfo("token", "ShouldBeRemovedToken");
        ssoUser.addUserInfo("upstreamToken", "ShouldBeRemovedUpstreamToken");
        ssoUser.addUserInfo(AUTHORIZATION_INFO, "ShouldBeRemovedAuthorizationInfo");

        ssoUser.addUserInfo("stringProperty", "StringPropertyValue");
        ssoUser.addUserInfo("longProperty", 123L);
        ssoUser.addUserInfo("booleanProperty", Boolean.TRUE);
        Date dateValue = new Date();
        ssoUser.addUserInfo("dateProperty", dateValue);
        List<String> stringList = new ArrayList<String>();
        stringList.add("JUnit");
        ssoUser.addUserInfo("listProperty", stringList);

        UserPrincipal userPrincipal = new UserPrincipal();
        ssoUser.addUserInfo("UserPrincipal", userPrincipal);
        when(jsonProviderMock.writeValue(userPrincipal)).thenReturn("UserPrincipalSerialization");

        Map<String, Object> claims = octopusSSOUserConverter.asClaims(ssoUser, jsonProviderMock);

        assertThat(claims).containsEntry("id", "IdValue");
        assertThat(claims).containsEntry("localId", "LocalIdValue");

        assertThat(claims).containsEntry(UserInfo.PREFERRED_USERNAME_CLAIM_NAME, "UserNameValue");

        assertThat(claims).containsEntry(UserInfo.FAMILY_NAME_CLAIM_NAME, "LastNameValue");
        assertThat(claims).containsEntry(UserInfo.GIVEN_NAME_CLAIM_NAME, "FirstNameValue");
        assertThat(claims).containsEntry(UserInfo.NAME_CLAIM_NAME, "FullNameValue");
        assertThat(claims).containsEntry(UserInfo.EMAIL_CLAIM_NAME, "EmailValue");

        assertThat(claims).containsEntry("stringProperty", "StringPropertyValue");
        assertThat(claims).containsEntry("longProperty", 123L);
        assertThat(claims).containsEntry("booleanProperty", Boolean.TRUE);
        assertThat(claims).containsEntry("dateProperty", dateValue);
        assertThat(claims).containsEntry("listProperty", stringList);
        assertThat(claims).containsEntry("UserPrincipal", "be.c4j.ee.security.model.UserPrincipal@UserPrincipalSerialization");

    }

    @Test
    public void fromUserInfo() {

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("id", "IdValue");
        jsonObject.put("localId", "LocalIdValue");

        jsonObject.put(UserInfo.PREFERRED_USERNAME_CLAIM_NAME, "UserNameValue");

        jsonObject.put(UserInfo.FAMILY_NAME_CLAIM_NAME, "LastNameValue");
        jsonObject.put(UserInfo.GIVEN_NAME_CLAIM_NAME, "FirstNameValue");
        jsonObject.put(UserInfo.NAME_CLAIM_NAME, "FullNameValue");
        jsonObject.put(UserInfo.EMAIL_CLAIM_NAME, "john.doe@acme.com");

        jsonObject.put("stringProperty", "StringPropertyValue");
        jsonObject.put("longProperty", 123L);
        jsonObject.put("booleanProperty", Boolean.TRUE);
        Date dateValue = new Date();
        jsonObject.put("dateProperty", dateValue);

        List<String> stringList = new ArrayList<String>();
        stringList.add("JUnit");

        jsonObject.put("listProperty", stringList);
        jsonObject.put("UserPrincipal", "be.c4j.ee.security.model.UserPrincipal@UserPrincipalSerialization");

        jsonObject.put("sub", "RequiredByOpenIDConnectSpec");
        UserInfo userInfo = new UserInfo(jsonObject);

        UserPrincipal userPrincipal = new UserPrincipal("RequiredId", "userName", "Name");
        when(jsonProviderMock.readValue("UserPrincipalSerialization", UserPrincipal.class)).thenReturn(userPrincipal);
        OctopusSSOUser ssoUser = octopusSSOUserConverter.fromUserInfo(userInfo, jsonProviderMock);

        assertThat(ssoUser.getId()).isEqualTo("IdValue");
        assertThat(ssoUser.getLocalId()).isEqualTo("LocalIdValue");

        assertThat(ssoUser.getUserName()).isEqualTo("UserNameValue");

        assertThat(ssoUser.getLastName()).isEqualTo("LastNameValue");
        assertThat(ssoUser.getFirstName()).isEqualTo("FirstNameValue");
        assertThat(ssoUser.getFullName()).isEqualTo("FullNameValue");
        assertThat(ssoUser.getEmail()).isEqualTo("john.doe@acme.com");

        assertThat(ssoUser.getUserInfo()).containsEntry("stringProperty", "StringPropertyValue");
        assertThat(ssoUser.getUserInfo()).containsEntry("longProperty", "123");
        assertThat(ssoUser.getUserInfo()).containsEntry("booleanProperty", "true");
        assertThat(ssoUser.getUserInfo()).containsEntry("dateProperty", dateValue.toString());
        assertThat(ssoUser.getUserInfo()).containsEntry("listProperty", "[JUnit]");
        assertThat(ssoUser.getUserInfo()).containsEntry("UserPrincipal", userPrincipal);

    }

    @Test
    public void fromUserInfo_ForCredentialOwner() {

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("id", "IdValue");
        jsonObject.put("localId", "LocalIdValue");

        jsonObject.put("sub", "RequiredByOpenIDConnectSpec");
        UserInfo userInfo = new UserInfo(jsonObject);

        OctopusSSOUser ssoUser = octopusSSOUserConverter.fromUserInfo(userInfo, jsonProviderMock);

        assertThat(ssoUser.getId()).isEqualTo("IdValue");
        assertThat(ssoUser.getLocalId()).isEqualTo("LocalIdValue");

        assertThat(ssoUser.getUserName()).isEqualTo("RequiredByOpenIDConnectSpec");

    }

}