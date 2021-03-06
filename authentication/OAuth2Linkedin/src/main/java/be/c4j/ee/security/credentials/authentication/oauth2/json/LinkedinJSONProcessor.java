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
package be.c4j.ee.security.credentials.authentication.oauth2.json;

import be.c4j.ee.security.credentials.authentication.oauth2.OAuth2User;
import be.c4j.ee.security.credentials.authentication.oauth2.info.OAuth2UserInfoProcessor;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.apache.shiro.authz.UnauthenticatedException;

import javax.enterprise.context.ApplicationScoped;
import java.util.Arrays;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class LinkedinJSONProcessor extends OAuth2UserInfoProcessor {

    // Constants in this class are specific for LinkedIn and thus we don't put them in OctopusConstants
    private static final List<String> KEYS = Arrays.asList("id", "emailAddress", "publicProfileUrl", "pictureUrl");

    public OAuth2User extractLinkedinUser(String json) {
        OAuth2User oAuth2User = null;
        try {
            JSONParser parser = new JSONParser(JSONParser.MODE_PERMISSIVE);

            JSONObject jsonObject = (JSONObject) parser.parse(json);

            if (!jsonObject.containsKey("error")) {
                oAuth2User = new OAuth2User();
                oAuth2User.setId(getString(jsonObject, "id"));
                oAuth2User.setEmail(getString(jsonObject, "emailAddress"));

                oAuth2User.setFullName(optString(jsonObject, "lastName") + " " + optString(jsonObject, "firstName"));

                oAuth2User.setLink(optString(jsonObject, "publicProfileUrl"));

                oAuth2User.setPicture(optString(jsonObject, "pictureUrl"));

                processJSON(oAuth2User, jsonObject, KEYS);

            } else {
                logger.warn("Received following response from Linkedin token resolving \n" + json);
                throw new UnauthenticatedException(json);
            }

        } catch (ParseException e) {
            logger.warn(e.getMessage(), e);
        }
        return oAuth2User;
    }

}
