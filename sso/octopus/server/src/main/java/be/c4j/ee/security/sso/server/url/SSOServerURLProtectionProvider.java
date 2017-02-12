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
package be.c4j.ee.security.sso.server.url;

import be.c4j.ee.security.url.ProgrammaticURLProtectionProvider;

import javax.enterprise.context.ApplicationScoped;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class SSOServerURLProtectionProvider implements ProgrammaticURLProtectionProvider {


    @Override
    public Map<String, String> getURLEntriesToAdd() {
        Map<String, String> result = new HashMap<String, String>();
        // For the rest authentication
        result.put("/data/octopus/rest/user", "anon");
        // For the rest endpoints retrieving user info / permissions
        result.put("/data/octopus/sso/permissions/*", "anon");
        result.put("/data/octopus/**", "ssoFilter, user");
        //URL Which triggers Login
        result.put("/octopus/**", "ssoAuthFilter, user");

        return result;
    }
}
