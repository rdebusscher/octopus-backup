/*
 * Copyright 2014-2016 Rudy De Busscher (www.c4j.be)
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
 *
 */
package be.c4j.ee.security.credentials.authentication.oauth2.google.json;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.credentials.authentication.oauth2.info.OAuth2UserInfoProcessor;
import org.apache.shiro.authz.UnauthenticatedException;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import javax.enterprise.context.ApplicationScoped;
import java.util.Arrays;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class GoogleJSONProcessor extends OAuth2UserInfoProcessor {

    private static final List<String> KEYS = Arrays.asList("sub", "email", "verified_email", "family_name", "given_name", "name", "hd", "link", "picture", "gender", "locale");

    public OAuth2User extractGoogleUser(String json) {
        OAuth2User oAuth2User = null;
        try {
            JSONObject jsonObject = new JSONObject(new JSONTokener(json));

            if (!jsonObject.has("error")) {
                oAuth2User = new OAuth2User();
                oAuth2User.setId(jsonObject.getString("sub"));
                oAuth2User.setEmail(jsonObject.getString("email"));

                oAuth2User.setVerifiedEmail(jsonObject.optBoolean("verified_email"));
                oAuth2User.setLastName(jsonObject.optString("family_name"));
                oAuth2User.setFirstName(jsonObject.optString("given_name"));
                oAuth2User.setFullName(jsonObject.optString("name"));
                oAuth2User.setDomain(jsonObject.optString("hd"));
                oAuth2User.setLink(jsonObject.optString("link"));
                oAuth2User.setPicture(jsonObject.optString("picture"));
                oAuth2User.setGender(jsonObject.optString("gender"));
                oAuth2User.setLocale(jsonObject.optString("locale"));

                processJSON(oAuth2User, jsonObject, KEYS);
            } else {
                logger.warn("Received following response from Google token resolving \n" + json);
                throw new UnauthenticatedException(json);
            }

        } catch (JSONException e) {
            logger.warn(e.getMessage(), e);
        }
        return oAuth2User;
    }

}
