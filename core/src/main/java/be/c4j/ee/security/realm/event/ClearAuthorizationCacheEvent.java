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
package be.c4j.ee.security.realm.event;

import be.c4j.ee.security.PublicAPI;
import be.c4j.ee.security.model.UserPrincipal;

import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@PublicAPI
public class ClearAuthorizationCacheEvent {
    private UserPrincipal userPrincipal;

    private Map<String, Object> info = new HashMap<String, Object>();

    public ClearAuthorizationCacheEvent(UserPrincipal userPrincipal) {
        this.userPrincipal = userPrincipal;
    }

    public UserPrincipal getUserPrincipal() {
        return userPrincipal;
    }

    public void addInfo(String key, Object value) {
        info.put(key, value);
    }

    public Object getInfo(String key) {
        return info.get(key);
    }
}
