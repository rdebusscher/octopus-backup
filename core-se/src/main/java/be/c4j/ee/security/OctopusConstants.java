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
package be.c4j.ee.security;

/**
 *
 */
@PublicAPI
public final class OctopusConstants {

    public static final String AUTHORIZATION_HEADER = "Authorization";

    public static final String AUTHORIZATION_INFO = "authorizationInfo";
    public static final String AUTHENTICATION_TOKEN = "authenticationToken";

    public static final String MOBILE_NUMBER = "mobileNumber";
    public static final String FIRST_NAME = "firstName";
    public static final String LAST_NAME = "lastName";
    public static final String FULL_NAME = "fullName";
    public static final String EMAIL = "email";
    public static final String EXTERNAL_ID = "externalId";
    public static final String LOCAL_ID = "localId";  // TODO is there a difference and how correctly used (LocalId vs ExternalId)

    public static final String PICTURE = "picture";
    public static final String GENDER = "gender";
    public static final String LOCALE = "locale";
    public static final String TOKEN = "token";
    public static final String UPSTREAM_TOKEN = "upstreamToken";

    public static final String DOMAIN = "domain";
    public static final String OAUTH2_TOKEN = "OAuth2token";

    public static final String OCTOPUS_AUTHENTICATED = "OctopusAuthenticated";
    public static final String OCTOPUS_REFERER = "OctopusReferer";

    public static final String X_API_KEY = "x-api-key";
    public static final String BEARER = "Bearer";

    public static final String CALLER_GROUPS = "callerGroups";

    private OctopusConstants() {
    }
}
