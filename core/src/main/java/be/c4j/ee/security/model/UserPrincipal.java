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
package be.c4j.ee.security.model;

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.exception.OctopusIllegalActionException;

import javax.enterprise.inject.Typed;
import java.io.Serializable;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@Typed
@PublicAPI
public class UserPrincipal implements Principal, Serializable {

    private Serializable id;
    private String userName;
    private String name;
    private boolean systemAccount = false;
    private Boolean needsTwoStepAuthentication;

    private Map<String, Object> userInfo = new HashMap<String, Object>();

    public UserPrincipal() {
        // Weld needs this to make a proxy
    }

    /**
     * Regular creation of the user principal for a user which has identified itself.
     *
     * @param id       unique id of the user.
     * @param userName The user name.
     * @param name     The name.
     */
    public UserPrincipal(Serializable id, String userName, String name) {
        if (id == null) {
            throw new IllegalArgumentException("id cannot be null");
        }
        this.id = id;
        this.userName = userName;
        this.name = name;
    }

    /**
     * Creation of the user principal for a system account.
     *
     * @param systemAccount The system account name.
     */
    public UserPrincipal(String systemAccount) {
        this(systemAccount, systemAccount, systemAccount);
        this.systemAccount = true;
    }

    public Serializable getId() {
        return id;
    }

    @Override
    public String getName() {
        return name;
    }

    public void setName(String name) {
        if (this.name != null) {
            throw new OctopusIllegalActionException("Setting the name of the Principal isn't allowed since there is already a name specified");
        }
        this.name = name;
    }

    public String getUserName() {
        return userName;
    }

    public void addUserInfo(String key, Serializable value) {
        userInfo.put(key, value);
    }

    public void addUserInfo(Map<String, Object> values) {
        userInfo.putAll(values);
    }

    public <T> T getUserInfo(String key) {
        return (T) userInfo.get(key);
    }

    public Map<String, Object> getInfo() {
        return userInfo;
    }

    public boolean isSystemAccount() {
        return systemAccount;
    }

    public void setNeedsTwoStepAuthentication(Boolean needsTwoStepAuthentication) {
        this.needsTwoStepAuthentication = needsTwoStepAuthentication;
    }

    public boolean needsTwoStepAuthentication() {
        boolean result = false;
        if (needsTwoStepAuthentication != null && needsTwoStepAuthentication) {
            result = true;
        }
        return result;
    }

    public String getMobileNumber() {
        Object value = userInfo.get(OctopusConstants.MOBILE_NUMBER);
        return value == null ? null : value.toString();
    }

    public String getFirstName() {
        Object value = userInfo.get(OctopusConstants.FIRST_NAME);
        return value == null ? null : value.toString();
    }

    public String getLastName() {
        Object value = userInfo.get(OctopusConstants.LAST_NAME);
        return value == null ? null : value.toString();
    }

    public String getFullName() {
        Object value = userInfo.get(OctopusConstants.FULL_NAME);
        return value == null ? null : value.toString();
    }

    public String getEmail() {
        Object value = userInfo.get(OctopusConstants.EMAIL);
        return value == null ? null : value.toString();
    }

    public String getExternalId() {
        Object value = userInfo.get(OctopusConstants.EXTERNAL_ID);
        return value == null ? null : value.toString();
    }

    @Override
    public boolean equals(Object o) {
        // Cannot be final as it is injected
        if (this == o) {
            return true;
        }
        if (!(o instanceof UserPrincipal)) {
            return false;
        }

        UserPrincipal that = (UserPrincipal) o;

        if (!id.equals(that.getId())) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        // Cannot be final as it is injected
        return id.hashCode();
    }

    @Override
    public String toString() {
        return name;
    }
}
