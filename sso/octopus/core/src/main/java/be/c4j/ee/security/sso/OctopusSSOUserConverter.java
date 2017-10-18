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

import be.c4j.ee.security.OctopusConstants;
import be.c4j.ee.security.sso.rest.PrincipalUserInfoJSONProvider;
import be.c4j.ee.security.sso.rest.reflect.Property;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.lang.reflect.Constructor;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static be.c4j.ee.security.OctopusConstants.AUTHORIZATION_INFO;
import static be.c4j.ee.security.OctopusConstants.LOCAL_ID;

/**
 * TODO On Java EE 8, use JSON-B for this.
 */
@ApplicationScoped
public class OctopusSSOUserConverter {

    private static final String MARKER_CUSTOM_CLASS = "@@";
    @Inject
    private Logger logger;

    private static final List<String> DEFAULT_PROPERTY_NAMES = Arrays.asList("id", OctopusConstants.LOCAL_ID, "userName", OctopusConstants.LAST_NAME, OctopusConstants.FIRST_NAME, OctopusConstants.FULL_NAME, OctopusConstants.EMAIL);

    public UserInfo fromIdToken(JWTClaimsSet idTokenClaims) {
        return new UserInfo(idTokenClaims);
    }

    public Map<String, Object> asClaims(OctopusSSOUser ssoUser, PrincipalUserInfoJSONProvider jsonProvider) {
        Map<String, Object> result = new HashMap<String, Object>();


        result.put("id", ssoUser.getId());
        result.put(LOCAL_ID, ssoUser.getLocalId());

        result.put(UserInfo.PREFERRED_USERNAME_CLAIM_NAME, ssoUser.getUserName());

        result.put(UserInfo.FAMILY_NAME_CLAIM_NAME, ssoUser.getLastName());
        result.put(UserInfo.GIVEN_NAME_CLAIM_NAME, ssoUser.getFirstName());
        result.put(UserInfo.NAME_CLAIM_NAME, ssoUser.getFullName());
        result.put(UserInfo.EMAIL_CLAIM_NAME, ssoUser.getEmail());

        Map<String, Object> info = new HashMap<String, Object>(ssoUser.getUserInfo());
        info.remove(OctopusConstants.TOKEN);
        info.remove(OctopusConstants.UPSTREAM_TOKEN);
        info.remove(AUTHORIZATION_INFO);

        for (Map.Entry<String, Object> infoEntry : info.entrySet()) {

            Object value = infoEntry.getValue();
            if (Property.isBasicPropertyType(value)) {
                result.put(infoEntry.getKey(), value);
            } else {
                result.put(infoEntry.getKey(), value.getClass().getName() + MARKER_CUSTOM_CLASS + jsonProvider.writeValue(value));
            }
        }

        return result;
    }

    public OctopusSSOUser fromUserInfo(UserInfo userInfo, PrincipalUserInfoJSONProvider jsonProvider) {
        OctopusSSOUser result = new OctopusSSOUser();
        result.setId(userInfo.getStringClaim("id"));
        Object localIdClaim = userInfo.getClaim(LOCAL_ID);
        result.setLocalId(localIdClaim == null ? null : localIdClaim.toString());  // Get String returns null for (short) numbers
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
                if (keyValue.contains(MARKER_CUSTOM_CLASS)) {

                    Class<?> aClass = tryToDefineClass(keyValue);
                    if (aClass != null) {
                        int markerPos = keyValue.indexOf(MARKER_CUSTOM_CLASS);
                        value = jsonProvider.readValue(keyValue.substring(markerPos + MARKER_CUSTOM_CLASS.length()), aClass);
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

        if (!checkDefaultConstructor(result)) {
            logger.warn(String.format("Reading serialized userInfo data failed for OctopusSSOUser as class %s doesn't have a default constructor", parts[0]));
            result = null;
        }

        return result;
    }

    private boolean checkDefaultConstructor(Class<?> aClass) {
        boolean result = false;
        for (Constructor<?> constructor : aClass.getConstructors()) {
            if (constructor.getParameterTypes().length == 0) {
                result = true;
            }
        }
        return result;
    }


    private static String getString(JSONObject jsonObject, String key) {
        Object keyValue = jsonObject.get(key);
        if (keyValue != null) {
            return keyValue.toString();
        } else {
            return "";
        }
    }

}
