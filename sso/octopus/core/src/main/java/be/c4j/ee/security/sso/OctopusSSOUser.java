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

import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.shiro.ValidatedAuthenticationToken;
import be.c4j.ee.security.token.AbstractOctopusAuthenticationToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;

import java.io.Serializable;

/**
 * Principal created when using the SSO feature. This is an additional Principal (next to UserPrincipal) hich is also avau-ilable
 * in the PrincipalCollection. <br/>
 * The userInfo map is not serialized.
 * <p>
 * TODO, Should be a *Token, but need to introduce this in a backwards compatible way (at least for a few versions)
 */
@PublicAPI
public class OctopusSSOUser extends AbstractOctopusAuthenticationToken implements ValidatedAuthenticationToken, Serializable {

    private String id;
    private String localId;
    private String userName;
    private BearerAccessToken bearerAccessToken;  // Client side only. For server side tokens are kept at OIDCStoreData
    private String cookieToken;

    private String lastName;
    private String firstName;

    private String email;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getLocalId() {
        return localId;
    }

    public void setLocalId(String localId) {
        this.localId = localId;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public BearerAccessToken getBearerAccessToken() {
        return bearerAccessToken;
    }

    public void setBearerAccessToken(BearerAccessToken bearerAccessToken) {
        this.bearerAccessToken = bearerAccessToken;
    }

    public String getAccessToken() {
        return bearerAccessToken.getValue();
    }

    public String getCookieToken() {
        return cookieToken;
    }

    public void setCookieToken(String cookieToken) {
        this.cookieToken = cookieToken;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public boolean isLoggedOn() {
        return id != null;
    }

    @Override
    public String toString() {
        return "OctopusSSOUser{" + "id='" + id + '\'' +
                ", localId='" + localId + '\'' +
                ", lastName='" + lastName + '\'' +
                ", fullName='" + fullName + '\'' +
                ", email='" + email + '\'' +
                ", firstName='" + firstName + '\'' +
                '}';
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return cookieToken;
    }

    @Override
    public boolean equals(Object o) {
        // Can't be final because of CDI
        if (this == o) {
            return true;
        }
        if (!(o instanceof OctopusSSOUser)) {
            return false;
        }

        OctopusSSOUser ssoUser = (OctopusSSOUser) o;

        // Important, we need to use the getters as o can be a proxy and sso.userName returns null!!
        if (userName != null ? !userName.equals(ssoUser.getUserName()) : ssoUser.getUserName() != null) {
            return false;
        }
        return id != null ? id.equals(ssoUser.getId()) : ssoUser.getId() == null;
    }

    @Override
    public int hashCode() {
        // Can't be final because of CDI
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (userName != null ? userName.hashCode() : 0);
        return result;
    }
}
