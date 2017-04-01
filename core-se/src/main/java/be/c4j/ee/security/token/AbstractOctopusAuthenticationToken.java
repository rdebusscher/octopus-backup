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
package be.c4j.ee.security.token;

import org.apache.shiro.authc.AuthenticationToken;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */

public abstract class AbstractOctopusAuthenticationToken implements AuthenticationToken, Principal {

    protected String fullName;

    protected Map<String, Object> userInfo = new HashMap<String, Object>();

    @Override
    public String getName() {
        return fullName;
    }

    public boolean implies(Subject subject) {

        if (subject == null) {
            return false;
        }

        return subject.getPrincipals().contains(this);
    }

    public void addUserInfo(String key, Object value) {
        userInfo.put(key, value);
    }

    public void addUserInfo(Map<String, Object> info) {
        userInfo.putAll(info);
    }

    public Map<String, Object> getUserInfo() {

        return userInfo;
    }

    public <T> T getUserInfo(String key) {
        return (T) userInfo.get(key);
    }

}
