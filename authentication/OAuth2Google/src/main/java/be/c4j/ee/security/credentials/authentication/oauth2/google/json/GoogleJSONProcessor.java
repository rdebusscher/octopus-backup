/*
 * Copyright 2014-2015 Rudy De Busscher (www.c4j.be)
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
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class GoogleJSONProcessor {

    @Inject
    private Logger logger;

    public OAuth2User extractGoogleUser(String json) {
        OAuth2User oAuth2User = null;
        try {
            JSONObject jsonObject = new JSONObject(new JSONTokener(json));

            if (!jsonObject.has("error")) {
                oAuth2User = new OAuth2User();
                oAuth2User.setId(jsonObject.getString("id"));
                oAuth2User.setEmail(jsonObject.getString("email"));
                oAuth2User.setVerifiedEmail(jsonObject.getBoolean("verified_email"));
                oAuth2User.setLastName(jsonObject.getString("family_name"));
                oAuth2User.setFirstName(jsonObject.getString("given_name"));
                oAuth2User.setFullName(jsonObject.getString("name"));
                if (jsonObject.has("hd")) {
                    oAuth2User.setDomain(jsonObject.getString("hd"));
                }
                oAuth2User.setLink(jsonObject.getString("link"));
                oAuth2User.setPicture(jsonObject.getString("picture"));
                if (jsonObject.has("gender")) {
                    oAuth2User.setGender(jsonObject.getString("gender"));
                }
                oAuth2User.setLocale(jsonObject.getString("locale"));
            } else {
                logger.warn("Received following response from Google token resolving \n" + json);
            }

        } catch (JSONException e) {
            logger.warn(e.getMessage(), e);
        }
        return oAuth2User;
    }

}
