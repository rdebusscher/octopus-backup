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

import be.c4j.ee.security.sso.rest.PrincipalUserInfoJSONProvider;
import be.c4j.ee.security.sso.rest.reflect.Property;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class OctopusSSOUserConverter {

    @Inject
    private Logger logger;

    private static final List<String> DEFAULT_PROPERTY_NAMES = Arrays.asList("id", OctopusSSOUser.LOCAL_ID, "userName", "lastName", "firstName", "fullName", "email");

    public UserInfo fromIdToken(JWTClaimsSet idTokenClaims) {
        return new UserInfo(idTokenClaims);
    }

    public Map<String, Object> asClaims(OctopusSSOUser ssoUser, PrincipalUserInfoJSONProvider jsonProvider) {
        Map<String, Object> result = new HashMap<String, Object>();


        result.put("id", ssoUser.getId());
        result.put("localId", ssoUser.getLocalId());

        result.put(UserInfo.PREFERRED_USERNAME_CLAIM_NAME, ssoUser.getUserName());

        result.put(UserInfo.FAMILY_NAME_CLAIM_NAME, ssoUser.getLastName());
        result.put(UserInfo.GIVEN_NAME_CLAIM_NAME, ssoUser.getFirstName());
        result.put(UserInfo.NAME_CLAIM_NAME, ssoUser.getFullName());
        result.put(UserInfo.EMAIL_CLAIM_NAME, ssoUser.getEmail());

        Map<String, Object> info = new HashMap<String, Object>(ssoUser.getUserInfo());
        info.remove("token"); // FIXME Create constant
        info.remove("upstreamToken"); // FIXME Create constant
        info.remove("authorizationInfo"); // FIXME Create constant

        for (Map.Entry<String, Object> infoEntry : info.entrySet()) {

            Object value = infoEntry.getValue();
            if (Property.isBasicPropertyType(value)) {
                result.put(infoEntry.getKey(), value);
            } else {
                result.put(infoEntry.getKey(), value.getClass().getName() + "@" + jsonProvider.writeValue(value));
            }
        }

        return result;
    }

    public OctopusSSOUser fromUserInfo(UserInfo userInfo, PrincipalUserInfoJSONProvider jsonProvider) {
        OctopusSSOUser result = new OctopusSSOUser();
        result.setId(userInfo.getStringClaim("id"));
        result.setLocalId(userInfo.getStringClaim("localId"));
        String username = userInfo.getPreferredUsername();
        // with resourceOwnerPasswordCredentials, username is in "sub"
        result.setUserName(username == null ? userInfo.getStringClaim("sub") : username);

        result.setLastName(userInfo.getFamilyName());
        result.setFirstName(userInfo.getGivenName());
        result.setFullName(userInfo.getName());
        result.setEmail(userInfo.getEmailAddress());


        Object value;


        JSONObject jsonObject = userInfo.toJSONObject();
        for (String keyName : jsonObject.keySet()) {

            if (!DEFAULT_PROPERTY_NAMES.contains(keyName)) {
                String keyValue = getString(jsonObject, keyName);
                if (keyValue.contains("@")) {

                    Class<?> aClass = tryToDefineClass(keyValue);
                    if (aClass != null) {
                        int markerPos = keyValue.indexOf('@');
                        value = jsonProvider.readValue(keyValue.substring(markerPos + 1), aClass);
                    } else {
                        value = keyValue; // We don't have the class, we keep the string representation for convenience.
                    }

                } else {
                    value = keyValue;
                }
                result.addUserInfo(keyName, value);
            }
        }


        return result;
    }

    private Class<?> tryToDefineClass(String keyValue) {
        Class<?> result = null;
        String[] parts = keyValue.split("@", 2);
        try {
            result = Class.forName(parts[0]);
        } catch (ClassNotFoundException e) {
            // Nothing to do here, we don't have that class on the classpath
            logger.warn(String.format("Reading serialized userInfo data failed for OctopusSSOUser as class %s can't be located", parts[0]));
        }

        return result;
    }


    private static String getString(JSONObject jsonObject, String key) {
        return jsonObject.get(key).toString();
    }

}
