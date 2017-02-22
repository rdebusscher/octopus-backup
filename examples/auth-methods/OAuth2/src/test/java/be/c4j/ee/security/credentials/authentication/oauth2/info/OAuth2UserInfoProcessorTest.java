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
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.junit.Before;
import org.junit.Test;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class OAuth2UserInfoProcessorTest {

    private OAuth2UserInfoProcessor processor;

    @Before
    public void setup() {
        processor = new OAuth2UserInfoProcessor() {
        };
    }

    @Test
    public void testProcessJSON() throws ParseException {

        OAuth2User user = new OAuth2User();
        List<String> keys = Collections.singletonList("key2");

        JSONParser parser = new JSONParser(JSONParser.MODE_PERMISSIVE);

        JSONObject json = (JSONObject) parser.parse("{ \"key1\" : \"value1\", \"key2\" : \"value2\", \"key3\" : \"value3\" }");

        processor.processJSON(user, json, keys);

        Map<Serializable, Serializable> userInfo = user.getUserInfo();
        assertThat(userInfo).hasSize(9);  // There are 7 other keys which are added by default

        assertThat(userInfo).containsEntry("key1", "value1");
        assertThat(userInfo).containsEntry("key3", "value3");
    }
}