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
package be.c4j.ee.security.credentials.authentication.oauth2.info;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;

import javax.inject.Inject;
import java.util.Iterator;
import java.util.List;

/**
 *
 */
public abstract class OAuth2UserInfoProcessor {

    @Inject
    protected Logger logger;

    protected void processJSON(OAuth2User oAuth2User, JSONObject jsonObject, List<String> excludeKeys) {
        Iterator<String> keys = jsonObject.keySet().iterator();
        String key;
        while (keys.hasNext()) {
            key = keys.next();
            if (!excludeKeys.contains(key)) {
                Object info = jsonObject.get(key);
                oAuth2User.addUserInfo(key, info);
            }
        }
    }

    protected String getString(JSONObject jsonObject, String key) {
        return jsonObject.get(key).toString();
    }

    protected String optString(JSONObject jsonObject, String key) {
        if (jsonObject.containsKey(key)) {
            return getString(jsonObject, key);
        } else {
            return null;
        }
    }
}
