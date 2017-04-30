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
package be.c4j.ee.security.credentials.authentication.oauth2.octopus.provider;

import com.github.scribejava.apis.google.GoogleToken;
import com.github.scribejava.core.extractors.OAuth2AccessTokenJsonExtractor;

import java.util.regex.Pattern;

/**
 * additionally parses OpenID id_token
 */
public class OctopusJsonTokenExtractor extends OAuth2AccessTokenJsonExtractor {

    private static final Pattern ID_TOKEN_REGEX_PATTERN = Pattern.compile("\"id_token\"\\s*:\\s*\"(\\S*?)\"");

    protected OctopusJsonTokenExtractor() {
    }

    private static class InstanceHolder {

        private static final OctopusJsonTokenExtractor INSTANCE = new OctopusJsonTokenExtractor();
    }

    public static OctopusJsonTokenExtractor instance() {
        return InstanceHolder.INSTANCE;
    }

    // TODO Check if the use of GoogleToken is OK here. Propbably because Google also supports OpenId, just like Octopus.
    @Override
    protected GoogleToken createToken(String accessToken, String tokenType, Integer expiresIn,
                                      String refreshToken, String scope, String response) {
        return new GoogleToken(accessToken, tokenType, expiresIn, refreshToken, scope,
                extractParameter(response, ID_TOKEN_REGEX_PATTERN, false), response);
    }
}
