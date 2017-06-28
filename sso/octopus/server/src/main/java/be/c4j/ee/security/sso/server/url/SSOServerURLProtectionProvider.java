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

import be.c4j.ee.security.sso.server.config.SSOServerConfiguration;
import be.c4j.ee.security.url.ProgrammaticURLProtectionProvider;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 *
 */
@ApplicationScoped
public class SSOServerURLProtectionProvider implements ProgrammaticURLProtectionProvider {

    @Inject
    private SSOServerConfiguration configuration;

    @Override
    public Map<String, String> getURLEntriesToAdd() {
        Map<String, String> result = new LinkedHashMap<String, String>();  // Keep order of insertion
        // For the rest endpoints retrieving user info / permissions
        result.put("/" + configuration.getSSOEndpointRoot() + "/octopus/sso/permissions/*", "noSessionCreation, anon");
        result.put("/" + configuration.getSSOEndpointRoot() + "/octopus/**", "noSessionCreation, ssoFilter, user");
        // URL related to OpenId Connect
        result.put("/octopus/sso/logout", "userRequired");  // So we need a user (from cookie) to be able to logout

        result.put("/octopus/sso/authenticate", "oidcFilter");
        result.put("/octopus/sso/token", String.format("rate[%s], oidcFilter", configuration.getOIDCEndpointRateLimit()));
        result.put("/octopus/testAuthentication", "anon");  // But the SSOCookieRemembermeManager does his job :)
        result.put("/octopus/**", "none");

        return result;
    }
}
